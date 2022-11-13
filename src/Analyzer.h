/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_SLPROCESSOR_H
#define SLPARSER_SLPROCESSOR_H

#include "SafeList.h"
#include "AddressMatcher.h"
#include "StringMatcher.h"

namespace Proofpoint {
class Analyzer {
 public:
  typedef std::unordered_map<SafeList::SBFieldType,PatternErrors> PatternErrorMap;
 public:
  explicit Analyzer(const SafeList &safelist, PatternErrors& errors);
  ~Analyzer() = default;
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
