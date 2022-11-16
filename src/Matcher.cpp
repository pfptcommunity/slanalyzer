/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "Matcher.h"
#include <iostream>
#include <iomanip>
Proofpoint::Matcher::Matcher(bool literal, bool case_sensitive, RE2::Anchor anchor)
{
	compiled = false;
	opt.set_literal(literal);
	opt.set_case_sensitive(case_sensitive);
	opt.set_log_errors(false);
	match = std::make_unique<RE2::Set>(opt, anchor);
}
void Proofpoint::Matcher::Add(const std::string& pattern, const size_t& index, std::vector<PatternError>& pattern_errors)
{
	std::string error;
	int i = match->Add(pattern, &error);
	if (i==-1) {
		pattern_errors.push_back({index, pattern, error});
		return;
	}
	map_to_sle.insert({i, index});
}
bool Proofpoint::Matcher::Match(const std::string& pattern, std::vector<std::size_t>& match_indexes)
{
	match_indexes.clear();
	if (!compiled) {
		match->Compile();
		compiled = true;
	}
	std::vector<int> m;
	bool matched = match->Match(pattern, &m);
	for (auto index : m) {
		match_indexes.emplace_back(map_to_sle[index]);
	}
	return matched;
}
std::size_t Proofpoint::Matcher::GetPatternCount()
{
	return map_to_sle.size();
}
