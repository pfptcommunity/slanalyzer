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

#include "IMatcher.h"
#include "GlobalList.h"
#include "Utils.h"
#include <unordered_map>

namespace Proofpoint {
class GlobalStringMatcher {
public:
	GlobalStringMatcher();
	void Add(GlobalList::MatchType type, const std::string& pattern, const std::size_t& index,PatternErrors<std::size_t>& pattern_errors);
	bool Match(bool inbound, const std::string& pattern, GlobalList::Entries& safe_list);
private:
	std::unordered_map<GlobalList::MatchType, std::shared_ptr<IMatcher<std::size_t>>> matchers;
};
}
#endif //SLANALYZER_STRINGMATCHER_H