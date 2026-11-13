#pragma once
#include <stdint.h>
typedef int (*RRVideoFrameCallback)(void *context, int width, int height,
    const uint8_t *y, int y_stride, const uint8_t *u, int u_stride,
    const uint8_t *v, int v_stride, int64_t pts_microseconds,
    int64_t duration_microseconds, int matrix, int full_range);
typedef int (*RRVideoCancelled)(void *context);
__attribute__((visibility("default"))) int rr_gallery_decode_video(int input_fd,
    RRVideoFrameCallback callback, void *context, int *has_audio,
    RRVideoCancelled cancelled, void *cancel_context);
__attribute__((visibility("default"))) int rr_gallery_decode_first_video_frame(int input_fd,
    RRVideoFrameCallback callback, void *context, RRVideoCancelled cancelled, void *cancel_context);
