#ifndef CPPAD_CG_TEST_PATTERN_TEST_MODEL_INCLUDED
#define	CPPAD_CG_TEST_PATTERN_TEST_MODEL_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2018 Joao Leal
 *    Copyright (C) 2013 Ciengis
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

namespace CppAD {

template<class Base>
class PatternTestModel {
public:
    virtual std::vector<AD<Base> > evaluateModel(const std::vector<AD<Base> >& x,
                                                 const std::vector<AD<Base> >& par,
                                                 size_t repeat) = 0;

    inline virtual ~PatternTestModel() = default;
};

template<class Base>
class DefaultPatternTestModel : public PatternTestModel<Base> {
private:
    std::vector<AD<Base> > (*model_)(const std::vector<AD<Base> >& x, const std::vector<AD<Base> >& par, size_t repeat);
public:

    explicit DefaultPatternTestModel(std::vector<AD<Base> > (*model)(const std::vector<AD<Base> >& x, const std::vector<AD<Base> >& par, size_t repeat)) :
        model_(model) {
    }

    std::vector<AD<Base> > evaluateModel(const std::vector<AD<Base> >& x,
                                         const std::vector<AD<Base> >& par,
                                         size_t repeat) override {
        return (*model_)(x, par, repeat);
    }
};

template<class Base>
class PatternTestModelWithAtom : public PatternTestModel<Base> {
private:
    std::vector<AD<Base> > (*model_)(const std::vector<AD<Base> >& x, const std::vector<AD<Base> >& par, size_t repeat, atomic_base<Base>& atom);
    atomic_base<Base>& atom_;
public:

    explicit PatternTestModelWithAtom(std::vector<AD<Base> > (*model)(const std::vector<AD<Base> >& x, const std::vector<AD<Base> >& par, size_t repeat, atomic_base<Base>& atom),
                                    atomic_base<Base>& atom) :
        model_(model),
        atom_(atom) {
    }

    std::vector<AD<Base> > evaluateModel(const std::vector<AD<Base> >& x,
                                         const std::vector<AD<Base> >& par,
                                         size_t repeat) override {
        return (*model_)(x, par, repeat, atom_);
    }

};
}

#endif