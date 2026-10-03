#pragma once

inline bool resolveRepeatForRadioRequest(bool current_repeat, bool has_repeat_field, bool requested_repeat,
                                         bool is_repeat_frequency) {
  if (has_repeat_field) {
    return requested_repeat;
  }
  return is_repeat_frequency && current_repeat;
}
