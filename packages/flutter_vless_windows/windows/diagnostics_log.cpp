#include "diagnostics_log.h"

#include <algorithm>
#include <sstream>
#include <vector>

namespace flutter_vless {

namespace {

bool IsUtf8Continuation(unsigned char byte) { return (byte & 0xC0) == 0x80; }

std::string SanitizeUtf8(const std::string &value) {
  std::string output;
  output.reserve(value.size());
  std::size_t index = 0;
  while (index < value.size()) {
    const unsigned char lead = static_cast<unsigned char>(value[index]);
    if (lead <= 0x7F) {
      output.push_back(value[index++]);
      continue;
    }

    std::size_t sequence_length = 0;
    if (lead >= 0xC2 && lead <= 0xDF) {
      sequence_length = 2;
    } else if (lead >= 0xE0 && lead <= 0xEF) {
      sequence_length = 3;
    } else if (lead >= 0xF0 && lead <= 0xF4) {
      sequence_length = 4;
    }
    if (sequence_length == 0 || index + sequence_length > value.size()) {
      ++index;
      continue;
    }

    const unsigned char second = static_cast<unsigned char>(value[index + 1]);
    bool valid = IsUtf8Continuation(second);
    if (lead == 0xE0) {
      valid = second >= 0xA0 && second <= 0xBF;
    } else if (lead == 0xED) {
      valid = second >= 0x80 && second <= 0x9F;
    } else if (lead == 0xF0) {
      valid = second >= 0x90 && second <= 0xBF;
    } else if (lead == 0xF4) {
      valid = second >= 0x80 && second <= 0x8F;
    }
    for (std::size_t offset = 2; valid && offset < sequence_length;
         ++offset) {
      valid = IsUtf8Continuation(
          static_cast<unsigned char>(value[index + offset]));
    }
    if (!valid) {
      ++index;
      continue;
    }

    output.append(value, index, sequence_length);
    index += sequence_length;
  }
  return output;
}

} // namespace

DiagnosticsLog &DiagnosticsLog::Instance() {
  static DiagnosticsLog instance;
  return instance;
}

DiagnosticsLog::Generation DiagnosticsLog::Reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  lines_.clear();
  stored_bytes_ = 0;
  return ++generation_;
}

DiagnosticsLog::Generation DiagnosticsLog::CurrentGeneration() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return generation_;
}

void DiagnosticsLog::Append(const std::string &source,
                            const std::string &message) {
  Append(CurrentGeneration(), source, message);
}

void DiagnosticsLog::Append(Generation generation, const std::string &source,
                            const std::string &message) {
  std::string safe_source = SanitizeUtf8(source);
  std::replace(safe_source.begin(), safe_source.end(), '\r', ' ');
  std::replace(safe_source.begin(), safe_source.end(), '\n', ' ');

  std::vector<std::string> new_lines;
  std::string current;
  for (char character : message) {
    if (character == '\r') {
      continue;
    }
    if (character == '\n') {
      if (!current.empty()) {
        new_lines.push_back(current);
        current.clear();
      }
      continue;
    }
    current.push_back(character);
  }
  if (!current.empty()) {
    new_lines.push_back(current);
  }
  if (new_lines.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (generation != generation_) {
    return;
  }
  for (std::string &line : new_lines) {
    if (line.size() > kMaxLineBytes) {
      std::size_t start = line.size() - kMaxLineBytes;
      while (start < line.size() &&
             (static_cast<unsigned char>(line[start]) & 0xC0) == 0x80) {
        ++start;
      }
      line.erase(0, start);
    }
    line = SanitizeUtf8(line);
    if (line.empty()) {
      continue;
    }
    line = "[" + safe_source + "] " + line;
    stored_bytes_ += line.size() + 1;
    lines_.push_back(std::move(line));
  }
  while (!lines_.empty() && stored_bytes_ > kMaxStoredBytes) {
    stored_bytes_ -= lines_.front().size() + 1;
    lines_.pop_front();
  }
}

std::string DiagnosticsLog::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (lines_.empty()) {
    return {};
  }

  std::vector<std::string> selected;
  std::size_t selected_bytes = 0;
  for (auto iterator = lines_.rbegin(); iterator != lines_.rend(); ++iterator) {
    const std::size_t line_bytes = iterator->size() + 1;
    if (!selected.empty() &&
        (selected.size() >= kMaxSnapshotLines ||
         selected_bytes + line_bytes > kMaxSnapshotBytes)) {
      break;
    }
    selected.push_back(*iterator);
    selected_bytes += line_bytes;
  }

  std::ostringstream output;
  output << "--- Windows Xray/tun2socks diagnostics ---\n";
  for (auto iterator = selected.rbegin(); iterator != selected.rend();
       ++iterator) {
    output << *iterator << '\n';
  }
  return output.str();
}

} // namespace flutter_vless
