#ifndef CPPAD_CG_TEST_EXPM1_INCLUDED
#define CPPAD_CG_TEST_EXPM1_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2015 Ciengis
 *
 *  CppADCodeGen is distributed under multiple licenses:
 *
 *   - Eclipse Public License Version 1.0 (EPL1), and
 *   - GNU General Public License Version 3 (GPL3).
 *
 *  EPL1 terms and conditions can be found in the file "epl-v10.txt", while
 *  terms and conditions for the GPL3 can be found in the file "gpl3.txt".
 * ----------------------------------------------------------------------------
 * Author: Joao Leal
 */

#include <assert.h>

template<class T>
CppAD::ADFun<T>* Expm1TestFunc(const std::vector<CppAD::AD<T> >& x) {
    using namespace CppAD;
    using CppAD::expm1;

    assert(x.size() == 1);

    // dependent variable vector, indices, and values
    std::vector< AD<T> > y(1);

    y[0] = expm1(x[0]);

    // define f : x -> y and vectors for derivative calculations
    return new ADFun<T> (x, y);
}

#endif