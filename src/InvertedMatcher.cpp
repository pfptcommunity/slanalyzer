/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "InvertedMatcher.h"
#include <iostream>
#include <iomanip>

Proofpoint::InvertedMatcher::InvertedMatcher(bool literal, bool case_sensitive, RE2::Anchor anchor) {
  compiled = false;
  opt.set_literal(literal);
  opt.set_case_sensitive(case_sensitive);
  opt.set_log_errors(false);
  match = std::make_unique<RE2::Set>(opt, anchor);
}
void Proofpoint::InvertedMatcher::Add(const std::string &pattern, const size_t &index,std::vector<PatternError>& errors) {
  std::string error;
  int i = match->Add(pattern, &error);
  if( i == -1 ) {
	errors.push_back({index,pattern,error});
	return;
  }
  map_to_sle.insert({i, index});
}
bool Proofpoint::InvertedMatcher::Match(const std::string &pattern, std::vector<std::size_t> &match_indexes) {
  match_indexes.clear();
  if (!compiled) {
	match->Compile();
	compiled = true;
  }
  std::vector<int> m;
  bool matched = !match->Match(pattern, &m);
  for (auto item : map_to_sle) {
	if (!std::binary_search(m.begin(), m.end(), item.first)) {
	  match_indexes.emplace_back(item.second);
	}
  }
  return matched;
}
std::size_t Proofpoint::InvertedMatcher::GetPatternCount() {
  return map_to_sle.size();
}
