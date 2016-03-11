#ifndef CPPAD_CG_EVALUATOR_AD_INCLUDED
#define CPPAD_CG_EVALUATOR_AD_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2016 Ciengis
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
namespace cg {

/**
 * Helper class for the specialization of Evaluator for an output active type of AD<>
 */
template<class ScalarIn, class ScalarOut>
class EvaluatorAD : public EvaluatorBase<ScalarIn, ScalarOut, CppAD::AD<ScalarOut> > {
public:
    typedef CppAD::AD<ScalarOut> ActiveOut;
    typedef EvaluatorBase<ScalarIn, ScalarOut, ActiveOut> Super;
protected:
    using Super::handler_;
    using Super::evalArrayCreationOperation;
protected:
    std::set<OperationNode<ScalarIn>*> evalsAtomic_;
    std::map<size_t, CppAD::atomic_base<ScalarOut>* > atomicFunctions_;
public:

    inline EvaluatorAD(CodeHandler<ScalarIn>& handler) :
        Super(handler) {
    }

    inline virtual ~EvaluatorAD() {
    }

    /**
     * Provides an atomic function.
     * 
     * @param id The atomic function ID
     * @param atomic The atomic function
     * @return True if an atomic function with the same ID was already
     *         defined, false otherwise.
     */
    virtual bool addAtomicFunction(size_t id, atomic_base<ScalarOut>& atomic) {
        bool exists = atomicFunctions_.find(id) != atomicFunctions_.end();
        atomicFunctions_[id] = &atomic;
        return exists;
    }

    virtual void addAtomicFunctions(const std::map<size_t, atomic_base<ScalarOut>* >& atomics) {
        for (const auto& it : atomics) {
            atomic_base<ScalarOut>* atomic = it.second;
            if (atomic != nullptr) {
                atomicFunctions_[it.first] = atomic;
            }
        }
    }

protected:

    /**
     * @throws CGException on an internal evaluation error
     */
    virtual void evalAtomicOperation(OperationNode<ScalarIn>& node) override {
        using CppAD::vector;

        if (evalsAtomic_.find(&node) != evalsAtomic_.end()) {
            return;
        }

        if (node.getOperationType() != CGOpCode::AtomicForward) {
            throw CGException("Evaluator can only handle zero forward mode for atomic functions");
        }

        const std::vector<size_t>& info = node.getInfo();
        const std::vector<Argument<ScalarIn> >& args = node.getArguments();
        CPPADCG_ASSERT_KNOWN(args.size() == 2, "Invalid number of arguments for atomic forward mode");
        CPPADCG_ASSERT_KNOWN(info.size() == 3, "Invalid number of information data for atomic forward mode");

        // find the atomic function
        size_t id = info[0];
        typename std::map<size_t, atomic_base<ScalarOut>* >::const_iterator itaf = atomicFunctions_.find(id);
        atomic_base<ScalarOut>* atomicFunction = nullptr;
        if (itaf != atomicFunctions_.end()) {
            atomicFunction = itaf->second;
        }

        if (atomicFunction == nullptr) {
            std::stringstream ss;
            ss << "No atomic function defined in the evaluator for ";
            const std::string* atomName = handler_.getAtomicFunctionName(id);
            if (atomName != nullptr) {
                ss << "'" << *atomName << "'";
            } else
                ss << "id '" << id << "'";
            throw CGException(ss.str());
        }

        size_t p = info[2];
        if (p != 0) {
            throw CGException("Evaluator can only handle zero forward mode for atomic functions");
        }
        const vector<ActiveOut>& ax = evalArrayCreationOperation(*args[0].getOperation());
        vector<ActiveOut>& ay = evalArrayCreationOperation(*args[1].getOperation());

        (*atomicFunction)(ax, ay);

        evalsAtomic_.insert(&node);
    }
};

/**
 * Specialization of Evaluator for an output active type of AD<>
 */
template<class ScalarIn, class ScalarOut>
class Evaluator<ScalarIn, ScalarOut, CppAD::AD<ScalarOut> > : public EvaluatorAD<ScalarIn, ScalarOut> {
public:
    typedef CppAD::AD<ScalarOut> ActiveOut;
    typedef EvaluatorAD<ScalarIn, ScalarOut> Super;
public:
    using EvaluatorAD<ScalarIn, ScalarOut>::EvaluatorAD; // use same constructor
};

} // END cg namespace
} // END CppAD namespace

#endif