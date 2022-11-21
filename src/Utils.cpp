/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "Utils.h"

std::vector<std::string_view> Proofpoint::Utils::split(std::string_view str, char d)
{
	std::vector<std::string_view> res;
	res.reserve(str.length()/2);
	const char* ptr = str.data();
	size_t size = 0;
	for (const char c : str) {
		if (c==d) {
			res.emplace_back(ptr, size);
			ptr += size+1;
			size = 0;
			continue;
		}
		++size;
	}
	if (size)
		res.emplace_back(ptr, size);
	return res;
}

void Proofpoint::Utils::reverse(std::string& str){
	std::reverse(str.begin(),str.end());
}

void Proofpoint::Utils::ltrim(std::string& s)
{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
	  return !std::isspace(ch);
	}));
}

void Proofpoint::Utils::rtrim(std::string& s)
{
	s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
	  return !std::isspace(ch);
	}).base(), s.end());
}

void Proofpoint::Utils::trim(std::string& s)
{
	rtrim(s);
	ltrim(s);
}

std::string Proofpoint::Utils::reverse_copy(std::string str){
	std::reverse(str.begin(),str.end());
	return std::move(str);
}

std::string Proofpoint::Utils::ltrim_copy(std::string s)
{
	ltrim(s);
	return std::move(s);
}

std::string Proofpoint::Utils::rtrim_copy(std::string s)
{
	rtrim(s);
	return std::move(s);
}

std::string Proofpoint::Utils::trim_copy(std::string s)
{
	trim(s);
	return std::move(s);
}