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
#include "AddressMatcher.h"
#include "StringMatcher.h"

namespace Proofpoint {
class GlobalAnalyzer {
public:
	typedef std::unordered_map<GlobalList::FieldType, PatternErrors> PatternErrorMap;
public:
	explicit GlobalAnalyzer(const GlobalList& safelist, PatternErrors& pattern_errors);
	~GlobalAnalyzer() = default;
	void Process(const std::string& ss_file, GlobalList& safelist);
private:
	AddressMatcher ip;
	StringMatcher host;
	StringMatcher helo;
	StringMatcher hfrom;
	StringMatcher from;
	StringMatcher rcpt;
};
}
#endif //SLANALYZER_ANALYZER_H
