/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_STRINGMATCHER_H
#define SLPARSER_STRINGMATCHER_H

#include "IListMatcher.h"
#include "IMatcher.h"

namespace Proofpoint {
class StringMatcher : public IListMatcher {
 public:
  StringMatcher();
  void Add(SafeList::SBMatchType type, const std::string &pattern, const std::size_t &index, PatternErrors& errors) override;
  bool Match(const std::string &pattern, std::vector<std::shared_ptr<SafeList::SLEntry>> &safe_list) override;
 private:
  std::unordered_map<SafeList::SBMatchType, std::shared_ptr<IMatcher>> matchers;
};
}
#endif //SLPARSER_STRINGMATCHER_H