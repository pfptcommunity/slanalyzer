/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_ILISTMATCHER_H
#define SLANALYZER_ILISTMATCHER_H

#include "GlobalList.h"
#include "IMatcher.h"

namespace Proofpoint {
class IListMatcher {
public:
	virtual void Add(GlobalList::MatchType type,
			const std::string& pattern,
			const std::size_t& index,
			PatternErrors& pattern_errors) = 0;
	virtual bool Match(bool inbound, const std::string& pattern,
			GlobalList::Entries& safe_list) = 0;
};
}
#endif //SLANALYZER_ILISTMATCHER_H
