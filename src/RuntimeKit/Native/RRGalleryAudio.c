// Gallery audio decoder. The caller owns input and temporary output descriptors.
#include "RRGalleryAudio.h"
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/samplefmt.h>
#include <libswresample/swresample.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    FILE *file;
    RRGalleryAudioLimits limits;
    uint64_t bytes_read, start_ns, output_samples_limit;
    RRGalleryAudioResult stopped;
} Input;
static uint64_t now_ns(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
static int interrupted(void *opaque) {
    Input *in = opaque;
    if (in->stopped) return 1;
    if (in->limits.cancelled && in->limits.cancelled(in->limits.cancel_context)) in->stopped = RR_GALLERY_CANCELLED;
    else {
        uint64_t now = now_ns();
        if (!now || now - in->start_ns >= (uint64_t)in->limits.max_milliseconds * 1000000u) in->stopped = RR_GALLERY_LIMIT;
    }
    return in->stopped != 0;
}
static int input_read(void *opaque, uint8_t *buffer, int size) {
    Input *in = opaque;
    if (interrupted(in)) return AVERROR_EXIT;
    if (size <= 0) return AVERROR(EINVAL);
    if (in->bytes_read >= in->limits.max_read_bytes) { in->stopped = RR_GALLERY_LIMIT; return AVERROR_EXIT; }
    uint64_t remaining = in->limits.max_read_bytes - in->bytes_read;
    if ((uint64_t)size > remaining) size = (int)remaining;
    size_t n = fread(buffer, 1, (size_t)size, in->file); in->bytes_read += n;
    return n ? (int)n : (ferror(in->file) ? AVERROR(EIO) : AVERROR_EOF);
}
static int64_t input_seek(void *opaque, int64_t offset, int whence) {
    Input *in = opaque; FILE *f = in->file;
    if (interrupted(in)) return AVERROR_EXIT;
    if (whence == AVSEEK_SIZE) {
        off_t old = ftello(f); if (old < 0 || fseeko(f, 0, SEEK_END)) return AVERROR(EIO);
        off_t end = ftello(f); return fseeko(f, old, SEEK_SET) || end < 0 ? AVERROR(EIO) : end;
    }
    whence &= ~AVSEEK_FORCE;
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) return AVERROR(EINVAL);
    return fseeko(f, offset, whence) ? AVERROR(EIO) : ftello(f);
}
static int put32(FILE *f, uint32_t v) {
    uint8_t b[4] = { v, v >> 8, v >> 16, v >> 24 }; return fwrite(b, 1, 4, f) == 4 ? 0 : -1;
}
static int header(FILE *f, uint32_t bytes) {
    static const uint8_t fmt[] = { 'W','A','V','E','f','m','t',' ',16,0,0,0,1,0,2,0,68,172,0,0,16,177,2,0,4,0,16,0,'d','a','t','a' };
    return fseeko(f, 0, SEEK_SET) || fwrite("RIFF",1,4,f) != 4 || put32(f, bytes + 36) || fwrite(fmt,1,sizeof(fmt),f) != sizeof(fmt) || put32(f, bytes) ? -1 : 0;
}
static RRGalleryAudioResult convert(SwrContext *swr, AVFrame *frame, FILE *out, uint32_t *total, Input *in) {
    if (interrupted(in)) return in->stopped;
    int count = frame ? frame->nb_samples : 0, cap = swr_get_out_samples(swr, count);
    if (count < 0 || count > 1048576 || cap < 0 || cap > 1048576) return RR_GALLERY_LIMIT;
    if (!cap) return RR_GALLERY_OK;
    uint8_t *pcm = NULL;
    if (av_samples_alloc(&pcm, NULL, 2, cap, AV_SAMPLE_FMT_S16, 0) < 0) return RR_GALLERY_DECODE;
    int samples = swr_convert(swr, &pcm, cap, frame ? (const uint8_t **)frame->extended_data : NULL, count);
    RRGalleryAudioResult rc = RR_GALLERY_OK;
    if (samples < 0) rc = RR_GALLERY_DECODE;
    else {
        if (in->output_samples_limit) {
            uint64_t written = *total / 4;
            uint64_t remaining = written < in->output_samples_limit ? in->output_samples_limit - written : 0;
            if ((uint64_t)samples > remaining) samples = (int)remaining;
        }
        if ((uint64_t)*total + (uint64_t)samples * 4 > in->limits.max_output_bytes) rc = RR_GALLERY_LIMIT;
        else if (fwrite(pcm, 4, samples, out) != (size_t)samples) rc = RR_GALLERY_IO;
        else *total += (uint32_t)samples * 4;
    }
    av_freep(&pcm); return rc;
}
static int audio_timeline(AVFrame *frame, AVStream *stream, int sample_rate, int64_t *first_pts,
                          int64_t *next_us, int first) {
    if (frame->pts == AV_NOPTS_VALUE || sample_rate <= 0 || frame->nb_samples <= 0) return -1;
    int64_t pts_us = av_rescale_q(frame->pts, stream->time_base, (AVRational){1, 1000000});
    if (pts_us < -86400000000LL || pts_us > 86400000000LL) return -1;
    if (first) *first_pts = frame->pts;
    else if (pts_us < *next_us - 25000 || pts_us > *next_us + 25000) return -1;
    *next_us = pts_us + av_rescale_q(frame->nb_samples, (AVRational){1, sample_rate}, (AVRational){1, 1000000});
    return 0;
}
static RRGalleryAudioResult decode_audio(int input_fd, int output_fd, const RRGalleryAudioLimits *limits, int64_t *start_us) {
    struct stat source, destination;
    int output_flags = fcntl(output_fd, F_GETFL);
    if (!limits || !limits->max_input_bytes || !limits->max_read_bytes || !limits->max_milliseconds ||
        limits->max_output_bytes < 4 || limits->max_output_bytes > UINT32_MAX - 36 ||
        output_flags < 0 || (output_flags & O_APPEND) || (output_flags & O_ACCMODE) == O_RDONLY ||
        fstat(input_fd, &source) || fstat(output_fd, &destination) || !S_ISREG(source.st_mode) || !S_ISREG(destination.st_mode) ||
        source.st_size <= 0 || destination.st_size != 0 || (source.st_dev == destination.st_dev && source.st_ino == destination.st_ino)) return RR_GALLERY_INVALID;
    if ((uint64_t)source.st_size > limits->max_input_bytes) return RR_GALLERY_LIMIT;
    int64_t first_pts = AV_NOPTS_VALUE, next_audio_us = 0;
    Input input = { .limits = *limits, .start_ns = now_ns() };
    int in_copy = -1, out_copy = -1;
    FILE *out = NULL; AVFormatContext *format = NULL; AVCodecContext *decoder = NULL;
    AVIOContext *io = NULL; AVPacket *packet = NULL; AVFrame *frame = NULL; SwrContext *swr = NULL;
    RRGalleryAudioResult rc = RR_GALLERY_DECODE; int stream = -1, frames = 0, read_result = 0; uint32_t bytes = 0;
    if (!input.start_ns || interrupted(&input)) return input.stopped ? input.stopped : RR_GALLERY_IO;
    in_copy = dup(input_fd); out_copy = dup(output_fd);
    if (in_copy < 0 || out_copy < 0 || !(input.file = fdopen(in_copy, "rb"))) { rc = RR_GALLERY_IO; goto cleanup; }
    in_copy = -1;
    out = fdopen(out_copy, "wb");
    if (!out) { rc = RR_GALLERY_IO; goto cleanup; }
    out_copy = -1;
    if (fseeko(input.file, 0, SEEK_SET) || fseeko(out, 0, SEEK_SET)) { rc = RR_GALLERY_IO; goto cleanup; }
    format = avformat_alloc_context();
    uint8_t *buffer = av_malloc(32768);
    io = buffer ? avio_alloc_context(buffer, 32768, 0, &input, input_read, NULL, input_seek) : NULL;
    if (!io) av_free(buffer);
    if (!format || !io) goto cleanup;
    format->pb = io; format->flags |= AVFMT_FLAG_CUSTOM_IO;
    format->probesize = 1048576; format->max_analyze_duration = 5 * AV_TIME_BASE;
    format->interrupt_callback.callback = interrupted; format->interrupt_callback.opaque = &input;
    if (avformat_open_input(&format, NULL, NULL, NULL) < 0 || avformat_find_stream_info(format, NULL) < 0) goto cleanup;
    AVCodec *codec = NULL;
    stream = av_find_best_stream(format, AVMEDIA_TYPE_AUDIO, -1, -1, &codec, 0);
    if (stream < 0 || !codec || !(decoder = avcodec_alloc_context3(codec)) || avcodec_parameters_to_context(decoder, format->streams[stream]->codecpar) < 0 || (decoder->pkt_timebase = format->streams[stream]->time_base, avcodec_open2(decoder, codec, NULL) < 0)) goto cleanup;
    AVStream *audio = format->streams[stream];
    // Ogg Vorbis's final decoded frame can contain padding beyond the granule duration.
    if (decoder->codec_id == AV_CODEC_ID_VORBIS && format->iformat && !strcmp(format->iformat->name, "ogg") &&
        audio->duration > 0 && audio->time_base.num > 0 && audio->time_base.den > 0) {
        int64_t samples = av_rescale_q(audio->duration, audio->time_base, (AVRational){1, 44100});
        if (samples > 0 && samples <= UINT32_MAX / 4) input.output_samples_limit = (uint64_t)samples;
    }
    if (decoder->channels < 1 || decoder->channels > 8 || decoder->sample_rate < 8000 || decoder->sample_rate > 192000) { rc = RR_GALLERY_LIMIT; goto cleanup; }
    int64_t layout = decoder->channel_layout ? decoder->channel_layout : av_get_default_channel_layout(decoder->channels);
    swr = swr_alloc_set_opts(NULL, AV_CH_LAYOUT_STEREO, AV_SAMPLE_FMT_S16, 44100, layout, decoder->sample_fmt, decoder->sample_rate, 0, NULL);
    if (!swr || swr_init(swr) < 0 || !(packet = av_packet_alloc()) || !(frame = av_frame_alloc()) || header(out, 0)) goto cleanup;
    while ((read_result = av_read_frame(format, packet)) >= 0) {
        if (interrupted(&input)) goto cleanup;
        if (packet->stream_index == stream) {
            if (avcodec_send_packet(decoder, packet) < 0) { rc = RR_GALLERY_DECODE; goto cleanup; }
            int got;
            while ((got = avcodec_receive_frame(decoder, frame)) == 0) {
                if (start_us && audio_timeline(frame, audio, decoder->sample_rate, &first_pts, &next_audio_us, frames == 0)) { rc = RR_GALLERY_DECODE; goto cleanup; }
                rc = convert(swr, frame, out, &bytes, &input); if (rc) goto cleanup;
                frames++; av_frame_unref(frame);
            }
            if (got != AVERROR(EAGAIN) && got != AVERROR_EOF) { rc = RR_GALLERY_DECODE; goto cleanup; }
        }
        av_packet_unref(packet);
    }
    if (read_result != AVERROR_EOF || interrupted(&input)) { rc = RR_GALLERY_DECODE; goto cleanup; }
    if (avcodec_send_packet(decoder, NULL) < 0) { rc = RR_GALLERY_DECODE; goto cleanup; }
    int got;
    while ((got = avcodec_receive_frame(decoder, frame)) == 0) {
        if (start_us && audio_timeline(frame, audio, decoder->sample_rate, &first_pts, &next_audio_us, frames == 0)) { rc = RR_GALLERY_DECODE; goto cleanup; }
        rc = convert(swr, frame, out, &bytes, &input); if (rc) goto cleanup;
        frames++; av_frame_unref(frame);
    }
    if (got != AVERROR(EAGAIN) && got != AVERROR_EOF) { rc = RR_GALLERY_DECODE; goto cleanup; }
    rc = convert(swr, NULL, out, &bytes, &input);
    if (rc || !frames || !bytes) { if (!rc) rc = RR_GALLERY_DECODE; goto cleanup; }
    if (header(out, bytes) || fflush(out)) { rc = RR_GALLERY_IO; goto cleanup; }
    if (start_us) {
        if (first_pts == AV_NOPTS_VALUE) { rc = RR_GALLERY_DECODE; goto cleanup; }
        *start_us = av_rescale_q(first_pts, audio->time_base, (AVRational){1, 1000000});
    }
    rc = RR_GALLERY_OK;
cleanup:
    if (input.stopped) rc = input.stopped;
    if (out && fclose(out) && !rc) rc = RR_GALLERY_IO;
    if (rc && out && ftruncate(output_fd, 0)) rc = RR_GALLERY_IO;
    if (input.file) fclose(input.file);
    if (in_copy >= 0) close(in_copy);
    if (out_copy >= 0) close(out_copy);
    swr_free(&swr); av_packet_free(&packet); av_frame_free(&frame); avcodec_free_context(&decoder); avformat_close_input(&format); avio_context_free(&io);
    return rc;
}

RRGalleryAudioResult rr_gallery_decode_audio(int input_fd, int output_fd, const RRGalleryAudioLimits *limits) {
    return decode_audio(input_fd, output_fd, limits, NULL);
}
RRGalleryAudioResult rr_gallery_decode_audio_timed(int input_fd, int output_fd, const RRGalleryAudioLimits *limits, int64_t *start_us) {
    if (!start_us) return RR_GALLERY_INVALID;
    return decode_audio(input_fd, output_fd, limits, start_us);
}
