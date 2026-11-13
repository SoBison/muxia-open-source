#pragma once
#include <stdint.h>

// The caller supplies separate, already-open regular file descriptors; output must
// be a new empty file. The function does not close either caller-owned descriptor.
// Cancellation may be called from the decoding thread. It must be thread-safe.
typedef int (*RRGalleryAudioCancelled)(void *context);
typedef struct {
    uint64_t max_input_bytes;
    uint64_t max_read_bytes;
    uint32_t max_output_bytes;
    uint32_t max_milliseconds;
    RRGalleryAudioCancelled cancelled;
    void *cancel_context;
} RRGalleryAudioLimits;

typedef enum { RR_GALLERY_OK = 0, RR_GALLERY_INVALID = -1, RR_GALLERY_LIMIT = -2,
               RR_GALLERY_CANCELLED = -3, RR_GALLERY_DECODE = -4, RR_GALLERY_IO = -5 } RRGalleryAudioResult;
__attribute__((visibility("default"))) RRGalleryAudioResult rr_gallery_decode_audio(int input_fd, int output_fd, const RRGalleryAudioLimits *limits);

__attribute__((visibility("default"))) RRGalleryAudioResult rr_gallery_decode_audio_timed(int input_fd, int output_fd, const RRGalleryAudioLimits *limits, int64_t *start_us);
