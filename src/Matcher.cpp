/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slparser
 * @version 1.0.0
 * @license MIT
 */
#include "Matcher.h"

Proofpoint::Matcher::Matcher(bool literal, bool case_sensitive, RE2::Anchor anchor) {
  compiled = false;
  opt.set_literal(literal);
  opt.set_case_sensitive(case_sensitive);
  match = std::make_unique<RE2::Set>(opt, anchor);
}
void Proofpoint::Matcher::Add(const std::string &pattern, const size_t &index) {
  int i = match->Add(pattern, NULL);
  map_to_sle.insert({i, index});
}
bool Proofpoint::Matcher::Match(const std::string &pattern, std::vector<std::size_t> &match_indexes) {
  match_indexes.clear();
  if (!compiled) {
	match->Compile();
	compiled = true;
  }
  std::vector<int> m;
  bool matched = match->Match(pattern, &m);
  for (auto index : m) {
	match_indexes.push_back(map_to_sle[index]);
  }
  return matched;
}
std::size_t Proofpoint::Matcher::GetPatternCount() {
  return map_to_sle.size();
}
