#ifndef CPPAD_CG_CODE_HANDLER_LOOPS_INCLUDED
#define CPPAD_CG_CODE_HANDLER_LOOPS_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2013 Ciengis
 *
 *  CppADCodeGen is distributed under multiple licenses:
 *
 *   - Common Public License Version 1.0 (CPL1), and
 *   - GNU General Public License Version 2 (GPL2).
 *
 * CPL1 terms and conditions can be found in the file "epl-v10.txt", while
 * terms and conditions for the GPL2 can be found in the file "gpl2.txt".
 * ----------------------------------------------------------------------------
 * Author: Joao Leal
 */

namespace CppAD {

    template<class Base>
    void CodeHandler<Base>::registerLoop(LoopAtomicFun<Base>& loop) {
        _loops[loop.getLoopId()] = &loop;
    }

    template<class Base>
    LoopAtomicFun<Base>* CodeHandler<Base>::getLoop(size_t loopId) const {
        typename std::map<size_t, LoopAtomicFun<Base>*>::const_iterator it = _loops.find(loopId);
        if (it != _loops.end()) {
            return it->second;
        }

        return NULL;
    }

    template<class Base>
    size_t CodeHandler<Base>::addLoopDependentIndexPattern(const IndexPattern& pattern) {
        size_t size = _loopDependentIndexPatterns.size();
        if (_loopDependentIndexPatterns.capacity() == size) {
            _loopDependentIndexPatterns.reserve((size * 3) / 2 + 1);
        }
        _loopDependentIndexPatterns.push_back(&pattern);

        return size;
    }

    template<class Base>
    void CodeHandler<Base>::manageLoopDependentIndexPattern(const IndexPattern* pattern) {
        size_t sizeM = _loopDependentIndexPatternManaged.size();
        if (_loopDependentIndexPatternManaged.capacity() == sizeM) {
            _loopDependentIndexPatternManaged.reserve((sizeM * 3) / 2 + 1);
        }
        _loopDependentIndexPatternManaged.push_back(pattern);
    }
}

#endif