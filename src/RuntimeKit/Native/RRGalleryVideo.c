// Gallery video decoder. The caller owns the source descriptor.
#include "RRGalleryVideo.h"
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/intreadwrite.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { FILE *file; uint64_t read, deadline; int stopped; RRVideoCancelled cancelled; void *cancel_context; } Input;
static uint64_t monotonic_ns(void) { struct timespec t; return clock_gettime(CLOCK_MONOTONIC, &t) ? 0 : (uint64_t)t.tv_sec * 1000000000u + t.tv_nsec; }
static int stop(void *opaque) { Input *in = opaque; uint64_t now = monotonic_ns(); return in->stopped || (in->cancelled && in->cancelled(in->cancel_context)) || !now || now >= in->deadline; }
static int read_file(void *opaque, uint8_t *buf, int size) {
    Input *in = opaque;
    if (stop(in)) return AVERROR_EXIT;
    if (size <= 0) return AVERROR(EINVAL);
    if (in->read >= 256u * 1024u * 1024u) { in->stopped = 1; return AVERROR_EXIT; }
    uint64_t available = 256u * 1024u * 1024u - in->read;
    if ((uint64_t)size > available) size = (int)available;
    size_t n = fread(buf, 1, size, in->file); in->read += n;
    return n ? (int)n : (ferror(in->file) ? AVERROR(EIO) : AVERROR_EOF);
}
static int64_t seek_file(void *opaque, int64_t offset, int whence) {
    Input *in = opaque; FILE *f = in->file;
    if (stop(in)) return AVERROR_EXIT;
    if (whence == AVSEEK_SIZE) { off_t old=ftello(f); if (old<0 || fseeko(f,0,SEEK_END)) return AVERROR(EIO); off_t end=ftello(f); return fseeko(f,old,SEEK_SET) || end<0 ? AVERROR(EIO) : end; }
    whence &= ~AVSEEK_FORCE;
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) return AVERROR(EINVAL);
    return fseeko(f,offset,whence) ? AVERROR(EIO) : ftello(f);
}
typedef struct { int count; int64_t first_pts, last_pts; AVStream *stream; RRVideoFrameCallback callback; void *context; } Output;
static int render(Output *out, AVFrame *frame) {
    if (frame->width < 1 || frame->height < 1 || frame->width > 1920 || frame->height > 1080 || out->count >= 18000) return -1;
    int ten_bit = frame->format == AV_PIX_FMT_YUV420P10LE;
    if (!ten_bit && frame->format != AV_PIX_FMT_YUV420P && frame->format != AV_PIX_FMT_YUVJ420P) return -1;
    int bytes_per_sample = ten_bit ? 2 : 1;
    if (!frame->data[0] || !frame->data[1] || !frame->data[2] ||
        frame->linesize[0] < frame->width * bytes_per_sample ||
        frame->linesize[1] < ((frame->width+1)/2) * bytes_per_sample || frame->linesize[2] < ((frame->width+1)/2) * bytes_per_sample ||
        frame->linesize[0] > 32768 || frame->linesize[1] > 32768 || frame->linesize[2] > 32768) return -1;
    if (frame->best_effort_timestamp == AV_NOPTS_VALUE) return -1;
    int64_t pts = av_rescale_q(frame->best_effort_timestamp, out->stream->time_base, (AVRational){1,1000000});
    if (pts < -86400000000LL || pts > 86400000000LL) return -1;
    if (out->count && pts <= out->last_pts) return -1;
    if (!out->count) out->first_pts = pts;
    else if (pts - out->first_pts > 1800000000LL) return -1;
    int64_t duration = frame->pkt_duration > 0 ? av_rescale_q(frame->pkt_duration, out->stream->time_base, (AVRational){1,1000000}) : 0;
    if (duration < 0 || duration > 60000000) return -1;
    enum AVColorSpace space = out->stream->codecpar->color_space;
    if (space == AVCOL_SPC_UNSPECIFIED) space = frame->colorspace;
    int matrix;
    if (space == AVCOL_SPC_BT709) matrix = 709;
    else if (space == AVCOL_SPC_BT470BG || space == AVCOL_SPC_SMPTE170M || space == AVCOL_SPC_UNSPECIFIED) matrix = 601;
    else return -1;
    enum AVColorRange range = out->stream->codecpar->color_range;
    if (range == AVCOL_RANGE_UNSPECIFIED) range = frame->color_range;
    if (range != AVCOL_RANGE_UNSPECIFIED && range != AVCOL_RANGE_MPEG && range != AVCOL_RANGE_JPEG) return -1;
    int full_range = range == AVCOL_RANGE_JPEG || (range == AVCOL_RANGE_UNSPECIFIED && frame->format == AV_PIX_FMT_YUVJ420P);
    enum AVColorPrimaries primary = out->stream->codecpar->color_primaries;
    if (primary == AVCOL_PRI_UNSPECIFIED) primary = frame->color_primaries;
    if (primary != AVCOL_PRI_UNSPECIFIED && primary != AVCOL_PRI_BT709 && primary != AVCOL_PRI_SMPTE170M && primary != AVCOL_PRI_BT470BG) return -1;
    if ((matrix == 709 && primary != AVCOL_PRI_UNSPECIFIED && primary != AVCOL_PRI_BT709) ||
        (matrix == 601 && primary != AVCOL_PRI_UNSPECIFIED && primary != AVCOL_PRI_SMPTE170M)) return -1;
    enum AVColorTransferCharacteristic transfer = out->stream->codecpar->color_trc;
    if (transfer == AVCOL_TRC_UNSPECIFIED) transfer = frame->color_trc;
    if (transfer != AVCOL_TRC_UNSPECIFIED && transfer != AVCOL_TRC_BT709 && transfer != AVCOL_TRC_SMPTE170M) return -1;
    const uint8_t *planes[3] = { frame->data[0], frame->data[1], frame->data[2] };
    int strides[3] = { frame->linesize[0], frame->linesize[1], frame->linesize[2] };
    uint8_t *converted = NULL;
    if (ten_bit) {
        int widths[3] = { frame->width, (frame->width + 1) / 2, (frame->width + 1) / 2 };
        int heights[3] = { frame->height, (frame->height + 1) / 2, (frame->height + 1) / 2 };
        size_t y_size = (size_t)widths[0] * heights[0], c_size = (size_t)widths[1] * heights[1];
        converted = av_malloc(y_size + 2 * c_size);
        if (!converted) return -1;
        uint8_t *output[3] = { converted, converted + y_size, converted + y_size + c_size };
        for (int p = 0; p < 3; ++p) {
            for (int row = 0; row < heights[p]; ++row) {
                const uint8_t *src = frame->data[p] + (size_t)row * frame->linesize[p];
                uint8_t *dst = output[p] + (size_t)row * widths[p];
                for (int col = 0; col < widths[p]; ++col) {
                    unsigned int value = (AV_RL16(src + 2 * col) + 2) >> 2;
                    dst[col] = value > 255 ? 255 : value;
                }
            }
            planes[p] = output[p]; strides[p] = widths[p];
        }
    }
    int failed = out->callback && out->callback(out->context, frame->width, frame->height,
        planes[0], strides[0], planes[1], strides[1], planes[2], strides[2], pts, duration, matrix, full_range);
    av_free(converted);
    if (failed) return -1;
    out->last_pts=pts; out->count++; return 0;
}
static int decode_video(int input_fd, RRVideoFrameCallback callback, void *context, int *has_audio, RRVideoCancelled cancelled, void *cancel_context, int first_only) {
    if (!callback || !has_audio) return 2;
    int fd=dup(input_fd); if (fd<0) return 2;
    Input input = {0}; input.cancelled=cancelled; input.cancel_context=cancel_context; input.file=fdopen(fd,"rb");
    if (!input.file) { close(fd); return 2; }
    struct stat st; if (fstat(fileno(input.file),&st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 128*1024*1024) { fclose(input.file); return 2; }
    if (fseeko(input.file,0,SEEK_SET)) { fclose(input.file); return 2; }
    input.deadline=monotonic_ns()+(first_only ? 30000000000ull : 120000000000ull);
    AVFormatContext *format=avformat_alloc_context(); AVIOContext *io=NULL; AVCodecContext *codec_ctx=NULL; AVFrame *frame=NULL; AVPacket *packet=NULL; Output out={0}; int rc=1, stream=-1, result=0;
    uint8_t *buffer=av_malloc(32768); io=buffer?avio_alloc_context(buffer,32768,0,&input,read_file,NULL,seek_file):NULL; if(!io) av_free(buffer);
    if (!format || !io) goto done;
    format->pb=io; format->flags|=AVFMT_FLAG_CUSTOM_IO; format->probesize=1048576; format->max_analyze_duration=5*AV_TIME_BASE; format->interrupt_callback=(AVIOInterruptCB){stop,&input};
    if (avformat_open_input(&format,NULL,NULL,NULL)<0 || avformat_find_stream_info(format,NULL)<0) goto done;
    AVCodec *decoder=NULL; stream=av_find_best_stream(format,AVMEDIA_TYPE_VIDEO,-1,-1,&decoder,0);
    if(stream<0 || !decoder || !(codec_ctx=avcodec_alloc_context3(decoder)) || avcodec_parameters_to_context(codec_ctx,format->streams[stream]->codecpar)<0 || avcodec_open2(codec_ctx,decoder,NULL)<0) goto done;
    out.stream=format->streams[stream];
    if (out.stream->time_base.num <= 0 || out.stream->time_base.den <= 0) goto done;
    out.callback=callback; out.context=context; int audio_present=av_find_best_stream(format,AVMEDIA_TYPE_AUDIO,-1,-1,NULL,0)>=0; *has_audio=audio_present;
    if (!(packet=av_packet_alloc()) || !(frame=av_frame_alloc())) goto done;
    while((result=av_read_frame(format,packet))>=0) {
        if(stop(&input)) goto done;
        if(packet->stream_index==stream) {
            int side_size=0; if(av_packet_get_side_data(packet,AV_PKT_DATA_MATROSKA_BLOCKADDITIONAL,&side_size) && side_size>0) goto done;
            if(avcodec_send_packet(codec_ctx,packet)<0) goto done;
            int got; while((got=avcodec_receive_frame(codec_ctx,frame))==0) { if(stop(&input) || render(&out,frame)) goto done; av_frame_unref(frame); if (first_only) { rc=0; goto done; } }
            if(got!=AVERROR(EAGAIN) && got!=AVERROR_EOF) goto done;
        }
        av_packet_unref(packet);
    }
    if(result!=AVERROR_EOF || stop(&input) || avcodec_send_packet(codec_ctx,NULL)<0) goto done;
    while((result=avcodec_receive_frame(codec_ctx,frame))==0) { if(stop(&input) || render(&out,frame)) goto done; av_frame_unref(frame); if (first_only) { rc=0; goto done; } }
    if((result!=AVERROR(EAGAIN) && result!=AVERROR_EOF) || !out.count) goto done;
    rc=0;
done:
    av_packet_free(&packet); av_frame_free(&frame); avcodec_free_context(&codec_ctx); avformat_close_input(&format); avio_context_free(&io); fclose(input.file); return rc;
}

int rr_gallery_decode_video(int input_fd, RRVideoFrameCallback callback, void *context, int *has_audio, RRVideoCancelled cancelled, void *cancel_context) {
    return decode_video(input_fd, callback, context, has_audio, cancelled, cancel_context, 0);
}

int rr_gallery_decode_first_video_frame(int input_fd, RRVideoFrameCallback callback, void *context, RRVideoCancelled cancelled, void *cancel_context) {
    int has_audio = 0;
    return decode_video(input_fd, callback, context, &has_audio, cancelled, cancel_context, 1);
}

