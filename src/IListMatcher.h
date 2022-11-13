#ifndef SLPARSER_SRC_ILISTMATCHER_H_
#define SLPARSER_SRC_ILISTMATCHER_H_

#include "SafeList.h"
namespace Proofpoint {
class IListMatcher {
 public:
  virtual void Add(SafeList::SBMatchType type, const std::string &pattern, const std::size_t &index) = 0;
  virtual bool Match(const std::string &pattern, std::vector<std::shared_ptr<SafeList::SLEntry>> &safe_list) = 0;
};
}
#endif //SLPARSER_SRC_ILISTMATCHER_H_
