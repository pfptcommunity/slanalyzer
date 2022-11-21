/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_ANALYZER_H
#define SLANALYZER_ANALYZER_H

#include "GlobalList.h"
#include "GlobalAddressMatcher.h"
#include "GlobalStringMatcher.h"

namespace Proofpoint {
class GlobalAnalyzer {
public:
	typedef std::unordered_map<GlobalList::FieldType, PatternErrors<std::size_t>> PatternErrorMap;
public:
	GlobalAnalyzer() = default;
	~GlobalAnalyzer() = default;
	void Load(const GlobalList& safelist, PatternErrors<std::size_t>& pattern_errors);
	std::size_t Process(const std::string& ss_file, GlobalList& safelist, std::size_t& records_processed);
private:
	GlobalAddressMatcher ip;
	GlobalStringMatcher host;
	GlobalStringMatcher helo;
	GlobalStringMatcher hfrom;
	GlobalStringMatcher from;
	GlobalStringMatcher rcpt;
};
}
#endif //SLANALYZER_ANALYZER_H
