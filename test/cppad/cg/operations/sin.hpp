#ifndef CPPAD_CG_TEST_SIN_INCLUDED
#define CPPAD_CG_TEST_SIN_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2012 Ciengis
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
CppAD::ADFun<T>* SinFunc(const std::vector<CppAD::AD<T> >& U) {
    using CppAD::sin;
    using CppAD::cos;
    using namespace CppAD;

    // independent variable vector
    assert(U.size() == 1);

    // dependent variable vector 
    std::vector< AD<T> > Z(1);
    Z[0] = sin(U[0]);

    // create f: U -> Z and vectors used for derivative calculations
    return new ADFun<T>(U, Z);
}

#endif