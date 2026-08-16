#pragma once

#include "five_tuple.h"
#include <xxhash.h>
#include <cstddef> //for std::size_t

namespace NetHex {

    // A custom Functor to replace the slow std::hash
    struct XxHashFunctor {

        // Overloading the () operator allows the Hash Map to "call" this struct 
        // exactly like a normal function every time a new packet arrives.
        std::size_t operator()(const FiveTuple& tuple) const {

            // XXH64 arguments: (Pointer to data, Size of data in bytes, Seed value)
            // Because we used #pragma pack(1) on FiveTuple, we can safely hash 
            // the entire struct as one continuous block of raw memory!
            return XXH64(&tuple, sizeof(FiveTuple), 0);
        }
    };
}