#ifndef SLPARSER_SLPROCESSOR_H
#define SLPARSER_SLPROCESSOR_H

#include "SafeList.h"
#include "AddressMatcher.h"
#include "StringMatcher.h"

namespace Proofpoint {
class Processor {
 public:
  explicit Processor(const SafeList &safelist);
  ~Processor() = default;
  void Process(const std::string &ss_file, SafeList &safelist);
 private:
  AddressMatcher ip;
  StringMatcher host;
  StringMatcher helo;
  StringMatcher hfrom;
  StringMatcher from;
  StringMatcher rcpt;
};
}
#endif //SLPARSER_SLPROCESSOR_H
