#include "StringMatcher.h"
#include "InvertedMatcher.h"
#include "Matcher.h"
#include <iostream>

Proofpoint::StringMatcher::StringMatcher()
	:
	matchers({{SafeList::SBMatchType::EQUAL, std::make_shared<Matcher>(true, false, RE2::ANCHOR_BOTH)},
				 {SafeList::SBMatchType::NOT_EQUAL, std::make_shared<InvertedMatcher>(true, false, RE2::ANCHOR_BOTH)},
				 {SafeList::SBMatchType::MATCH, std::make_shared<Matcher>(true, false, RE2::UNANCHORED)},
				 {SafeList::SBMatchType::NOT_MATCH, std::make_shared<InvertedMatcher>(true, false, RE2::UNANCHORED)},
				 {SafeList::SBMatchType::REGEX, std::make_shared<Matcher>(false, false, RE2::UNANCHORED)},
				 {SafeList::SBMatchType::NOT_REGEX,
					 std::make_shared<InvertedMatcher>(false, false, RE2::UNANCHORED)}}) {}
void Proofpoint::StringMatcher::Add(Proofpoint::SafeList::SBMatchType type,
									const std::string &pattern,
									const size_t &index) {
  using
  enum SafeList::SBMatchType;
  if (type==IS_IN_DOMAINSET || type==UNKNOWN) {
	std::cerr << "Unhandled SBMatchType" << std::endl;
	return;
  }
  matchers[type]->Add(pattern, index);
}
bool Proofpoint::StringMatcher::Match(const std::string &pattern,
									  std::vector<std::shared_ptr<SafeList::SLEntry>> &safe_list) {
  bool matched = false;
  for (auto m : matchers) {
	std::vector<std::size_t> match_indexes;
	if (m.second->GetPatternCount()) {
	  matched |= m.second->Match(pattern, match_indexes);
	  for (auto i : match_indexes) {
		auto mle = safe_list.at(i);
		mle->matches++;
	  }
	}
  }
  return matched;
}
