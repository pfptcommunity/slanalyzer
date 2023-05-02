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

void Proofpoint::Utils::ltrim(std::string& str)
{
	str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch) {
	  return !std::isspace(ch);
	}));
}

void Proofpoint::Utils::rtrim(std::string& str)
{
	str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch) {
	  return !std::isspace(ch);
	}).base(), str.end());
}

void Proofpoint::Utils::trim(std::string& str)
{
	rtrim(str);
	ltrim(str);
}

std::string Proofpoint::Utils::reverse_copy(std::string str){
	std::reverse(str.begin(),str.end());
	return str;
}

std::string Proofpoint::Utils::ltrim_copy(std::string str)
{
	ltrim(str);
	return str;
}

std::string Proofpoint::Utils::rtrim_copy(std::string str)
{
	rtrim(str);
	return str;
}

std::string Proofpoint::Utils::trim_copy(std::string str)
{
	trim(str);
	return str;
}