#ifndef SLPARSER_STRINGMATCHER_H
#define SLPARSER_STRINGMATCHER_H

#include "IListMatcher.h"
#include "IMatcher.h"
#include <unordered_map>

namespace Proofpoint {
class StringMatcher : IListMatcher {
 public:
  StringMatcher();
  void Add(SafeList::SBMatchType type, const std::string &pattern, const std::size_t &index) override;
  bool Match(const std::string &pattern, std::vector<std::shared_ptr<SafeList::SLEntry>> &safe_list) override;
 private:
  std::unordered_map<SafeList::SBMatchType, std::shared_ptr<IMatcher>> matchers;
};
}
#endif //SLPARSER_STRINGMATCHER_H