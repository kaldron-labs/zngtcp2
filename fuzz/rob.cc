/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <algorithm>
#include <cstdint>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "buf_owner.h"

#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_reorder.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

namespace {
void release_reorder_buf(ngtcp2_buf *buf, int allocator_owned,
                         void *user_data) {
  (void)user_data;

  if (!allocator_owned) {
    ngtcp2_buf_release_owner(buf);
  }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);
  FuzzBufOwners owners;
  ngtcp2_reorder reorder;
  uint64_t cont_offset = 0;

  ngtcp2_reorder_init(&reorder, release_reorder_buf, nullptr,
                      ngtcp2_mem_default());

  while (fuzzed_data_provider.remaining_bytes()) {
    switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 4)) {
    case 0: {
      auto datalen = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(
        0, std::min<size_t>(512, fuzzed_data_provider.remaining_bytes()));
      auto data = fuzzed_data_provider.ConsumeBytes<uint8_t>(datalen);
      auto owner = fuzz_buf_owner_add(owners, data.data(), data.size());
      uint8_t empty = 0;
      ngtcp2_buf buf;
      size_t nwrite;
      int rv;

      ngtcp2_buf_init(&buf, owner->data.empty() ? &empty : owner->data.data(),
                      owner->data.size(), NGTCP2_BUF_ORIGIN_APPLICATION,
                      NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_REORDER_RX, owner,
                      fuzz_buf_retain, fuzz_buf_release);
      buf.last = buf.end;

      rv = ngtcp2_buf_retain_owner(&buf);
      if (rv != 0) {
        break;
      }

      rv = ngtcp2_reorder_push(&reorder, &buf,
                               fuzzed_data_provider.ConsumeIntegral<uint64_t>(),
                               cont_offset, 0, &nwrite);
      if (rv != 0) {
        ngtcp2_buf_release_owner(&buf);
      }

      break;
    }
    case 1:
      cont_offset = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
      ngtcp2_reorder_remove_prefix(&reorder, cont_offset);
      break;
    case 2: {
      const ngtcp2_buf *buf;
      auto offset = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
      auto datalen = ngtcp2_reorder_data_at(&reorder, &buf, offset);

      if (datalen) {
        ngtcp2_reorder_pop(
          &reorder, offset,
          fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, datalen));
      }

      break;
    }
    case 3: {
      const ngtcp2_buf *buf;

      ngtcp2_reorder_data_at(&reorder, &buf,
                             fuzzed_data_provider.ConsumeIntegral<uint64_t>());
      break;
    }
    case 4:
      cont_offset = ngtcp2_reorder_first_gap_offset(&reorder, cont_offset);
      break;
    }
  }

  ngtcp2_reorder_free(&reorder);
  fuzz_buf_owners_check_balanced(owners);

  return 0;
}
