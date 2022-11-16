/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_STRINGMATCHER_H
#define SLANALYZER_STRINGMATCHER_H

#include "IListMatcher.h"
#include "IMatcher.h"
#include <unordered_map>

namespace Proofpoint {
class StringMatcher : public IListMatcher {
public:
	StringMatcher();
	void Add(SafeList::MatchType type, const std::string& pattern, const std::size_t& index, PatternErrors& errors) final;
	bool Match(bool inbound, const std::string& pattern, std::vector<std::shared_ptr<SafeList::Entry>>& safe_list) final;
private:
	std::unordered_map<SafeList::MatchType, std::shared_ptr<IMatcher>> matchers;
};
}
#endif //SLANALYZER_STRINGMATCHER_H