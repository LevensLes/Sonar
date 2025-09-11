#pragma once

#include <string>
#include <vector>
#include <queue>
#include <memory>
#include <map>
#include <cctype>

namespace AhoCorasick {

    template<typename CharT>
    struct TrieNode {
        std::map<CharT, std::unique_ptr<TrieNode<CharT>>> children;
        TrieNode<CharT>* failure_link = nullptr;
        std::vector<size_t> output_indices;
    };

    template<typename CharT>
    struct Match {
        size_t end_pos;
        size_t pattern_index;
        std::basic_string<CharT> pattern;
    };

    template<typename CharT, bool CaseInsensitive = false>
    class Trie {
    public:
        using StringT = std::basic_string<CharT>;
        using MatchT = Match<CharT>;

        Trie() : root(std::make_unique<TrieNode<CharT>>()) {}

        void insert(const StringT& pattern, size_t pattern_index) {
            TrieNode<CharT>* current = root.get();
            for (const auto& ch : pattern) {
                CharT c = CaseInsensitive ? std::tolower(static_cast<unsigned char>(ch)) : ch;
                if (current->children.find(c) == current->children.end()) {
                    current->children[c] = std::make_unique<TrieNode<CharT>>();
                }
                current = current->children[c].get();
            }
            current->output_indices.push_back(pattern_index);
            patterns.push_back(pattern);
        }

        void build_failure_links() {
            std::queue<TrieNode<CharT>*> q;
            for (auto const& [key, val] : root->children) {
                val->failure_link = root.get();
                q.push(val.get());
            }

            while (!q.empty()) {
                TrieNode<CharT>* current = q.front();
                q.pop();

                for (auto const& [key, child] : current->children) {
                    TrieNode<CharT>* temp_failure_link = current->failure_link;
                    while (temp_failure_link != nullptr && temp_failure_link->children.find(key) == temp_failure_link->children.end()) {
                        temp_failure_link = temp_failure_link->failure_link;
                    }

                    if (temp_failure_link == nullptr) {
                        child->failure_link = root.get();
                    }
                    else {
                        child->failure_link = temp_failure_link->children[key].get();
                    }

                    child->output_indices.insert(child->output_indices.end(),
                        child->failure_link->output_indices.begin(),
                        child->failure_link->output_indices.end());
                    q.push(child.get());
                }
            }
        }

        std::vector<MatchT> parse_text(const CharT* text, size_t text_len) const {
            std::vector<MatchT> matches;
            TrieNode<CharT>* current = root.get();

            for (size_t i = 0; i < text_len; ++i) {
                CharT c = CaseInsensitive ? std::tolower(static_cast<unsigned char>(text[i])) : text[i];

                while (current != nullptr && current->children.find(c) == current->children.end()) {
                    current = current->failure_link;
                }

                if (current == nullptr) {
                    current = root.get();
                    continue;
                }

                current = current->children[c].get();

                if (!current->output_indices.empty()) {
                    for (size_t index : current->output_indices) {
                        matches.push_back({ i, index, patterns[index] });
                    }
                }
            }
            return matches;
        }

    private:
        std::unique_ptr<TrieNode<CharT>> root;
        std::vector<StringT> patterns;
    };
} // namespace AhoCorasick