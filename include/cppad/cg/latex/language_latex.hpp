#ifndef CPPAD_CG_LANGUAGE_LATEX_INCLUDED
#define CPPAD_CG_LANGUAGE_LATEX_INCLUDED
/* --------------------------------------------------------------------------
 *  CppADCodeGen: C++ Algorithmic Differentiation with Source Code Generation:
 *    Copyright (C) 2014 Ciengis
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
 * Generates code for the Latex language.
 * Requires the amsmath and algorithm2e latex package.
 * 
 * @author Joao Leal
 */
template<class Base>
class LanguageLatex : public Language<Base> {
protected:
    static const std::string _C_STATIC_INDEX_ARRAY;
    static const std::string _C_SPARSE_INDEX_ARRAY;
    static const std::string _COMP_OP_LT;
    static const std::string _COMP_OP_LE;
    static const std::string _COMP_OP_EQ;
    static const std::string _COMP_OP_GE;
    static const std::string _COMP_OP_GT;
    static const std::string _COMP_OP_NE;
    static const std::string _ATOMIC_TX;
    static const std::string _ATOMIC_TY;
    static const std::string _ATOMIC_PX;
    static const std::string _ATOMIC_PY;
protected:
    //
    const std::unique_ptr<LanguageGenerationData<Base> >* _info;
    // Latex algorithm options
    std::string _algorithmEnvOptions;
    // current indentation
    std::string _indentation;
    // text before an individual equation line
    std::string _starteq;
    // text after an individual equation line
    std::string _endeq;
    // new line characters
    std::string _endline;
    // output stream for the generated source code
    std::ostringstream _code;
    // creates the variable names
    VariableNameGenerator<Base>* _nameGen;
    // auxiliary string stream
    std::ostringstream _ss;
    //
    size_t _independentSize;
    //
    size_t _minTemporaryVarID;
    // maps the variable IDs to the their position in the dependent vector
    // (some IDs may be the same as the independent variables when dep = indep)
    std::map<size_t, size_t> _dependentIDs;
    // the dependent variable vector
    const CppAD::vector<CG<Base> >* _dependent;
    // the temporary variables that may require a declaration
    std::map<size_t, OperationNode<Base>*> _temporary;
    // the operator used for assignment of dependent variables
    std::string _depAssignOperation;
    // whether or not to ignore assignment of constant zero values to dependent variables
    bool _ignoreZeroDepAssign;
    // the name of the file to be created without the extension
    std::string _filename;
    // the maximum number of assignment (~lines) per local file
    size_t _maxAssigmentsPerFile;
    //
    std::map<std::string, std::string>* _sources;
    // the values in the temporary array
    std::vector<const Argument<Base>*> _tmpArrayValues;
    // the values in the temporary sparse array
    std::vector<const Argument<Base>*> _tmpSparseArrayValues;
    // indexes defined as function arguments
    std::vector<const IndexDclrOperationNode<Base>*> _funcArgIndexes;
    std::vector<const LoopStartOperationNode<Base>*> _currentLoops;
    // the maximum precision used to print values
    size_t _parameterPrecision;
    //
    bool _useLatexAlign;
    // whether or not we are in an equation/align block
    bool _inEquationEnv;
private:
    std::string auxArrayName_;

public:

    /**
     * Creates a C language source code generator
     * 
     * @param varTypeName variable data type (e.g. double)
     */
    LanguageLatex() :
        _info(nullptr),
        _starteq("\\["),
        _endeq("\\]\\;"),
        _endline("\n"),
        _nameGen(nullptr),
        _independentSize(0),
        _dependent(nullptr),
        _depAssignOperation("="),
        _ignoreZeroDepAssign(false),
        _filename("algorithm"),
        _maxAssigmentsPerFile(0),
        _sources(nullptr),
        _parameterPrecision(std::numeric_limits<Base>::digits10),
        _useLatexAlign(false),
        _inEquationEnv(false) {
    }

    inline const std::string& getDependentAssignOperation() const {
        return _depAssignOperation;
    }

    inline void setDependentAssignOperation(const std::string& depAssignOperation) {
        _depAssignOperation = depAssignOperation;
    }

    inline bool isIgnoreZeroDepAssign() const {
        return _depAssignOperation;
    }

    inline void setIgnoreZeroDepAssign(bool ignore) {
        _ignoreZeroDepAssign = ignore;
    }

    virtual void setFilename(const std::string& name) {
        _filename = name;
    }

    virtual void setFunctionIndexArgument(const IndexDclrOperationNode<Base>& funcArgIndex) {
        _funcArgIndexes.resize(1);
        _funcArgIndexes[0] = &funcArgIndex;
    }

    virtual void setFunctionIndexArguments(const std::vector<const IndexDclrOperationNode<Base>*>& funcArgIndexes) {
        _funcArgIndexes = funcArgIndexes;
    }

    virtual const std::vector<const IndexDclrOperationNode<Base>*>& getFunctionIndexArguments() const {
        return _funcArgIndexes;
    }

    /**
     * Provides the maximum precision used to print constant values in the
     * generated source code
     * 
     * @return the maximum number of digits
     */
    virtual size_t getParameterPrecision() const {
        return _parameterPrecision;
    }

    /**
     * Defines the maximum precision used to print constant values in the
     * generated source code
     * 
     * @param p the maximum number of digits
     */
    virtual void setParameterPrecision(size_t p) {
        _parameterPrecision = p;
    }

    virtual void setMaxAssigmentsPerFunction(size_t maxAssigmentsPerFunction,
                                             std::map<std::string, std::string>* sources) {
        _maxAssigmentsPerFile = maxAssigmentsPerFunction;
        _sources = sources;
    }

    inline virtual ~LanguageLatex() {
    }

    /***************************************************************************
     *                               STATIC
     **************************************************************************/
    static inline void printIndexCondExpr(std::ostringstream& out,
                                          const std::vector<size_t>& info,
                                          const std::string& index) {
        CPPADCG_ASSERT_KNOWN(info.size() > 1 && info.size() % 2 == 0, "Invalid number of information elements for an index condition expression operation");

        size_t infoSize = info.size();
        for (size_t e = 0; e < infoSize; e += 2) {
            if (e > 0) {
                out << " \\vee "; // or
            }
            size_t min = info[e];
            size_t max = info[e + 1];
            if (min == max) {
                out << index << " == " << min;
            } else if (min == 0) {
                out << index << " \\le " << max;
            } else if (max == std::numeric_limits<size_t>::max()) {
                out << min << " \\le " << index;
            } else {
                if (infoSize != 2)
                    out << "(";
                
                if (max - min == 1)
                    out << min << " == " << index << " \\vee " << index << " == " << max;
                else
                    out << min << " \\le " << index << " \\wedge" << index << " \\le " << max;

                if (infoSize != 2)
                    out << ")";
            }
        }
    }

    /***************************************************************************
     * 
     **************************************************************************/

    inline void printStaticIndexArray(std::ostringstream& os,
                                      const std::string& name,
                                      const std::vector<size_t>& values);

    inline void printStaticIndexMatrix(std::ostringstream& os,
                                      const std::string& name,
                                      const std::map<size_t, std::map<size_t, size_t> >& values);

    /***************************************************************************
     * index patterns
     **************************************************************************/
    static inline void generateNames4RandomIndexPatterns(const std::set<RandomIndexPattern*>& randomPatterns);

    static inline void printRandomIndexPatternDeclaration(std::ostringstream& os,
                                                          const std::string& identation,
                                                          const std::set<RandomIndexPattern*>& randomPatterns);

    static inline std::string indexPattern2String(const IndexPattern& ip,
                                                  const IndexDclrOperationNode<Base>& index);

    static inline std::string indexPattern2String(const IndexPattern& ip,
                                                  const std::vector<const IndexDclrOperationNode<Base>*>& indexes);

    static inline std::string linearIndexPattern2String(const LinearIndexPattern& lip,
                                                        const IndexDclrOperationNode<Base>& index);

    /***************************************************************************
     *                              protected
     **************************************************************************/
protected:

    virtual void generateSourceCode(std::ostream& out,
                                    const std::unique_ptr<LanguageGenerationData<Base> >& info) override {
        using CppAD::vector;

        const bool multiFile = _maxAssigmentsPerFile > 0 && _sources != nullptr;

        // clean up
        _code.str("");
        _ss.str("");
        _temporary.clear();
        _inEquationEnv = false;
        auxArrayName_ = "";
        _currentLoops.clear();

        // save some info
        _info = &info;
        _independentSize = info->independent.size();
        _dependent = &info->dependent;
        _nameGen = &info->nameGen;
        _minTemporaryVarID = info->minTemporaryVarID;
        const vector<CG<Base> >& dependent = info->dependent;
        const std::vector<OperationNode<Base>*>& variableOrder = info->variableOrder;

        _tmpArrayValues.resize(_nameGen->getMaxTemporaryArrayVariableID());
        std::fill(_tmpArrayValues.begin(), _tmpArrayValues.end(), nullptr);
        _tmpSparseArrayValues.resize(_nameGen->getMaxTemporarySparseArrayVariableID());
        std::fill(_tmpSparseArrayValues.begin(), _tmpSparseArrayValues.end(), nullptr);

        /**
         * generate index array names (might be used for variable names)
         */
        generateNames4RandomIndexPatterns(info->indexRandomPatterns);

        /**
         * generate variable names
         */
        //generate names for the independent variables
        for (size_t j = 0; j < _independentSize; j++) {
            OperationNode<Base>& op = *info->independent[j];
            if (op.getName() == nullptr) {
                op.setName(_nameGen->generateIndependent(op));
            }
        }

        // generate names for the dependent variables (must be after naming independents)
        for (size_t i = 0; i < dependent.size(); i++) {
            OperationNode<Base>* node = dependent[i].getOperationNode();
            if (node != nullptr && node->getOperationType() != CGOpCode::LoopEnd && node->getName() == nullptr) {
                if (node->getOperationType() == CGOpCode::LoopIndexedDep) {
                    size_t pos = node->getInfo()[0];
                    const IndexPattern* ip = info->loopDependentIndexPatterns[pos];
                    node->setName(_nameGen->generateIndexedDependent(*node, *ip));

                } else {
                    node->setName(_nameGen->generateDependent(i));
                }
            }
        }

        /**
         * function variable declaration
         */
        const std::vector<FuncArgument>& indArg = _nameGen->getIndependent();
        const std::vector<FuncArgument>& depArg = _nameGen->getDependent();
        const std::vector<FuncArgument>& tmpArg = _nameGen->getTemporary();
        CPPADCG_ASSERT_KNOWN(indArg.size() > 0 && depArg.size() > 0,
                             "There must be at least one dependent and one independent argument");
        CPPADCG_ASSERT_KNOWN(tmpArg.size() == 3,
                             "There must be three temporary variables");

        auxArrayName_ = tmpArg[1].name + "p";

        /**
         * Determine the dependent variables that result from the same operations
         */
        // dependent variables indexes that are copies of other dependent variables
        std::set<size_t> dependentDuplicates;

        for (size_t i = 0; i < dependent.size(); i++) {
            OperationNode<Base>* node = dependent[i].getOperationNode();
            if (node != nullptr) {
                CGOpCode type = node->getOperationType();
                if (type != CGOpCode::Inv && type != CGOpCode::LoopEnd) {
                    size_t varID = node->getVariableID();
                    if (varID > 0) {
                        std::map<size_t, size_t>::const_iterator it2 = _dependentIDs.find(varID);
                        if (it2 == _dependentIDs.end()) {
                            _dependentIDs[node->getVariableID()] = i;
                        } else {
                            // there can be several dependent variables with the same ID
                            dependentDuplicates.insert(i);
                        }
                    }
                }
            }
        }

        // the names of local functions
        std::vector<std::string> inputLatexFiles;
        if (multiFile) {
            inputLatexFiles.reserve(variableOrder.size() / _maxAssigmentsPerFile);
        }

        /**
         * non-constant variables
         */
        if (variableOrder.size() > 0) {
            // generate names for temporary variables
            for (OperationNode<Base>* node : variableOrder) {
                CGOpCode op = node->getOperationType();
                if (!isDependent(*node) && op != CGOpCode::IndexDeclaration) {
                    // variable names for temporaries must always be created since they might have been used before with a different name/id
                    if (requiresVariableName(*node) && op != CGOpCode::ArrayCreation && op != CGOpCode::SparseArrayCreation) {
                        node->setName(_nameGen->generateTemporary(*node));
                    } else if (op == CGOpCode::ArrayCreation) {
                        node->setName(_nameGen->generateTemporaryArray(*node));
                    } else if (op == CGOpCode::SparseArrayCreation) {
                        node->setName(_nameGen->generateTemporarySparseArray(*node));
                    }
                }
            }

            /**
             * Source code generation magic!
             */
            if (info->zeroDependents) {
                // zero initial values
                const std::vector<FuncArgument>& depArg = _nameGen->getDependent();
                if(!depArg.empty())
                    checkEquationEnvStart();
                for (size_t i = 0; i < depArg.size(); i++) {
                    _code << _starteq;
                    const FuncArgument& a = depArg[i];
                    if (a.array) {
                        _code <<  a.name;
                    } else {
                        _code << _nameGen->generateDependent(i);
                    }
                    _code << " = ";
                    printParameter(Base(0.0));
                    _code << _endeq << _endline;
                }
            }

            size_t assignCount = 0;
            for (OperationNode<Base>* it : variableOrder) {
                // check if a new function should start
                if (assignCount >= _maxAssigmentsPerFile && multiFile && _currentLoops.empty()) {
                    assignCount = 0;
                    saveLocalFunction(inputLatexFiles, inputLatexFiles.empty() && info->zeroDependents);
                }

                OperationNode<Base>& node = *it;

                // a dependent variable assigned by a loop does require any source code (its done inside the loop)
                if (node.getOperationType() == CGOpCode::DependentRefRhs) {
                    continue; // nothing to do (this operation is right hand side only)
                } else if (node.getOperationType() == CGOpCode::TmpDcl) { // temporary variable declaration does not need any source code here
                    continue; // nothing to do (bogus operation)
                }

                assignCount += printAssigment(node);
            }

            if (inputLatexFiles.size() > 0 && assignCount > 0) {
                assignCount = 0;
                saveLocalFunction(inputLatexFiles, false);
            }
        }

        if (!inputLatexFiles.empty()) {
            /**
             * Create the master latex file which inputs the other files
             */
            CPPADCG_ASSERT_KNOWN(tmpArg[0].array,
                                 "The temporary variables must be saved in an array in order to generate multiple functions");
            printAlgorithmStart(_code);
            for (size_t i = 0; i < inputLatexFiles.size(); i++) {
                _code << "\\input{" << inputLatexFiles[i] << "}" << _endline;
            }
            printAlgorithmEnd(_code);
        }

        // dependent duplicates
        if (dependentDuplicates.size() > 0) {
            _code << "% variable duplicates: " << dependentDuplicates.size() << _endline;
            for (size_t index : dependentDuplicates) {
                const CG<Base>& dep = (*_dependent)[index];
                std::string varName = _nameGen->generateDependent(index);
                const std::string& origVarName = *dep.getOperationNode()->getName();

                _code << varName << " " << _depAssignOperation << " " << origVarName;
                printAssigmentEnd();
            }
        }

        // constant dependent variables 
        bool commentWritten = false;
        for (size_t i = 0; i < dependent.size(); i++) {
            if (dependent[i].isParameter()) {
                if (!_ignoreZeroDepAssign || !dependent[i].isIdenticalZero()) {
                    if (!commentWritten) {
                        _code << "% dependent variables without operations" << _endline;
                        commentWritten = true;
                    }
                    std::string varName = _nameGen->generateDependent(i);
                    _code << varName << " " << _depAssignOperation << " ";
                    printParameter(dependent[i].getValue());
                    printAssigmentEnd();
                }
            } else if (dependent[i].getOperationNode()->getOperationType() == CGOpCode::Inv) {
                if (!commentWritten) {
                    _code << "% dependent variables without operations" << _endline;
                    commentWritten = true;
                }
                std::string varName = _nameGen->generateDependent(i);
                const std::string& indepName = *dependent[i].getOperationNode()->getName();
                _code << varName << " " << _depAssignOperation << " " << indepName;
                printAssigmentEnd(*dependent[i].getOperationNode());
            }
        }

        checkEquationEnvEnd();
        
        /**
         * encapsulate the code in a function
         */
            if (inputLatexFiles.empty()) {
                // a single source file
                _ss << "% Latex source file for '" << _filename << "' (automatically generated by CppADCodeGen)" << _endline;
                printAlgorithmStart(_ss);
                _ss << _code.str();
                printAlgorithmEnd(_ss);
                
                out << _ss.str();
                
                if (_sources != nullptr) {
                    (*_sources)[_filename + ".tex"] = _ss.str();
                }
            } else {
                // there are multiple source files (this last one is the master)
                (*_sources)[_filename + ".tex"] = _code.str();
            }
        
    }
    
    inline virtual void printAlgorithmStart(std::ostream& out) {
        out << "\\begin{algorithm}";
        if(!_algorithmEnvOptions.empty())
            out << "["<<_algorithmEnvOptions<<"]";
        out << _endline;
    }

    inline virtual void printAlgorithmEnd(std::ostream& out) {
        out << "\\end{algorithm}" << _endline;
    }    
    
    inline virtual void printEquationEnvStart() {
        if(_useLatexAlign)
            _code << "\\begin{align*}" << _endline;
    }
    
    inline virtual void printEquationEnvEnd() {
        if(_useLatexAlign)
            _code << "\\end{align*}" << _endline;
    }
    
    inline virtual void checkEquationEnvStart() {
        if(!_inEquationEnv) {
            printEquationEnvStart();
            _inEquationEnv = true;
        }
    }
    
    inline virtual void checkEquationEnvEnd() {
        if(_inEquationEnv) {
            printEquationEnvEnd();
            _inEquationEnv = false;
        }
    }

    inline unsigned printAssigment(OperationNode<Base>& node) {
        return printAssigment(node, node);
    }

    inline unsigned printAssigment(OperationNode<Base>& nodeName,
                                   const Argument<Base>& nodeRhs) {
        if (nodeRhs.getOperation() != nullptr) {
            return printAssigment(nodeName, *nodeRhs.getOperation());
        } else {
            printAssigmentStart(nodeName);
            printParameter(*nodeRhs.getParameter());
            printAssigmentEnd(nodeName);
            return 1;
        }
    }

    inline unsigned printAssigment(OperationNode<Base>& nodeName,
                                   OperationNode<Base>& nodeRhs) {
        bool createsVar = directlyAssignsVariable(nodeRhs); // do we need to do the assignment here?
        if (!createsVar) {
            printAssigmentStart(nodeName);
        }
        unsigned lines = printExpressionNoVarCheck(nodeRhs);
        if (!createsVar) {
            printAssigmentEnd(nodeRhs);
        }

        if (nodeRhs.getOperationType() == CGOpCode::ArrayElement) {
            OperationNode<Base>* array = nodeRhs.getArguments()[0].getOperation();
            size_t arrayId = array->getVariableID();
            size_t pos = nodeRhs.getInfo()[0];
            if (array->getOperationType() == CGOpCode::ArrayCreation)
                _tmpArrayValues[arrayId - 1 + pos] = nullptr; // this could probably be removed!
            else
                _tmpSparseArrayValues[arrayId - 1 + pos] = nullptr; // this could probably be removed!
        }

        return lines;
    }

    inline virtual void printAssigmentStart(OperationNode<Base>& op) {
        printAssigmentStart(op, createVariableName(op), isDependent(op));
    }

    inline virtual void printAssigmentStart(OperationNode<Base>& node, const std::string& varName, bool isDep) {
        if (!isDep) {
            _temporary[node.getVariableID()] = &node;
        }
        
        checkEquationEnvStart();

        _code << _starteq;
        _code << varName << " ";
        if (isDep) {
            CGOpCode op = node.getOperationType();
            if (op == CGOpCode::DependentMultiAssign || (op == CGOpCode::LoopIndexedDep && node.getInfo()[1] == 1)) {
                _code << "+=";
            } else {
                _code << _depAssignOperation;
            }
        } else {
            _code << "=";
        }
        _code << " ";
    }
    
    inline virtual void printAssigmentEnd() {
        _code << _endeq << _endline;
    }

    inline virtual void printAssigmentEnd(OperationNode<Base>& op) {
        printAssigmentEnd();
    }

    virtual void saveLocalFunction(std::vector<std::string>& localFuncNames,
                                   bool zeroDependentArray) {
        _ss << _filename << "__part_" << (localFuncNames.size() + 1);
        std::string funcName = _ss.str();
        _ss.str("");

        // loop indexes
        _nameGen->prepareCustomFunctionVariables(_ss);
        _ss << _code.str();
        _nameGen->finalizeCustomFunctionVariables(_ss);

        (*_sources)[funcName + ".tex"] = _ss.str();
        localFuncNames.push_back(funcName);

        _code.str("");
        _ss.str("");
    }

    virtual bool createsNewVariable(const OperationNode<Base>& var) const override {
        CGOpCode op = var.getOperationType();
        if (var.getTotalUsageCount() > 1) {
            return op != CGOpCode::ArrayElement && op != CGOpCode::Index && op != CGOpCode::IndexDeclaration && op != CGOpCode::Tmp;
        } else {
            return ( op == CGOpCode::ArrayCreation ||
                    op == CGOpCode::SparseArrayCreation ||
                    op == CGOpCode::AtomicForward ||
                    op == CGOpCode::AtomicReverse ||
                    op == CGOpCode::ComLt ||
                    op == CGOpCode::ComLe ||
                    op == CGOpCode::ComEq ||
                    op == CGOpCode::ComGe ||
                    op == CGOpCode::ComGt ||
                    op == CGOpCode::ComNe ||
                    op == CGOpCode::LoopIndexedDep ||
                    op == CGOpCode::LoopIndexedTmp ||
                    op == CGOpCode::IndexAssign ||
                    op == CGOpCode::Assign) &&
                    op != CGOpCode::CondResult;
        }
    }

    virtual bool requiresVariableName(const OperationNode<Base>& var) const {
        CGOpCode op = var.getOperationType();
        return (var.getTotalUsageCount() > 1 &&
                op != CGOpCode::AtomicForward &&
                op != CGOpCode::AtomicReverse &&
                op != CGOpCode::LoopStart &&
                op != CGOpCode::LoopEnd &&
                op != CGOpCode::Index &&
                op != CGOpCode::IndexAssign &&
                op != CGOpCode::StartIf &&
                op != CGOpCode::ElseIf &&
                op != CGOpCode::Else &&
                op != CGOpCode::EndIf &&
                op != CGOpCode::CondResult &&
                op != CGOpCode::LoopIndexedTmp &&
                op != CGOpCode::Tmp);
    }

    /**
     * Whether or not this operation assign its expression to a variable by
     * itself.
     * 
     * @param var the operation node
     * @return 
     */
    virtual bool directlyAssignsVariable(const OperationNode<Base>& var) const {
        CGOpCode op = var.getOperationType();
        return isCondAssign(op) ||
                op == CGOpCode::ArrayCreation ||
                op == CGOpCode::SparseArrayCreation ||
                op == CGOpCode::AtomicForward ||
                op == CGOpCode::AtomicReverse ||
                op == CGOpCode::DependentMultiAssign ||
                op == CGOpCode::LoopStart ||
                op == CGOpCode::LoopEnd ||
                op == CGOpCode::IndexAssign ||
                op == CGOpCode::StartIf ||
                op == CGOpCode::ElseIf ||
                op == CGOpCode::Else ||
                op == CGOpCode::EndIf ||
                op == CGOpCode::CondResult ||
                op == CGOpCode::IndexDeclaration;
    }

    virtual bool requiresVariableArgument(enum CGOpCode op, size_t argIndex) const override {
        return op == CGOpCode::CondResult;
    }

    inline const std::string& createVariableName(OperationNode<Base>& var) {
        CGOpCode op = var.getOperationType();
        CPPADCG_ASSERT_UNKNOWN(var.getVariableID() > 0);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::AtomicForward);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::AtomicReverse);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::LoopStart);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::LoopEnd);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::Index);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::IndexAssign);
        CPPADCG_ASSERT_UNKNOWN(op != CGOpCode::IndexDeclaration);

        if (var.getName() == nullptr) {
            if (op == CGOpCode::ArrayCreation) {
                var.setName(_nameGen->generateTemporaryArray(var));

            } else if (op == CGOpCode::SparseArrayCreation) {
                var.setName(_nameGen->generateTemporarySparseArray(var));

            } else if (op == CGOpCode::LoopIndexedDep) {
                size_t pos = var.getInfo()[0];
                const IndexPattern* ip = (*_info)->loopDependentIndexPatterns[pos];
                var.setName(_nameGen->generateIndexedDependent(var, *ip));

            } else if (op == CGOpCode::LoopIndexedIndep) {
                size_t pos = var.getInfo()[1];
                const IndexPattern* ip = (*_info)->loopIndependentIndexPatterns[pos];
                var.setName(_nameGen->generateIndexedIndependent(var, *ip));

            } else if (var.getVariableID() <= _independentSize) {
                // independent variable
                var.setName(_nameGen->generateIndependent(var));

            } else if (var.getVariableID() < _minTemporaryVarID) {
                // dependent variable
                std::map<size_t, size_t>::const_iterator it = _dependentIDs.find(var.getVariableID());
                CPPADCG_ASSERT_UNKNOWN(it != _dependentIDs.end());

                size_t index = it->second;
                var.setName(_nameGen->generateDependent(index));

            } else if (op == CGOpCode::LoopIndexedTmp || op == CGOpCode::Tmp) {
                CPPADCG_ASSERT_KNOWN(var.getArguments().size() >= 1, "Invalid number of arguments for loop indexed temporary operation");
                OperationNode<Base>* tmpVar = var.getArguments()[0].getOperation();
                CPPADCG_ASSERT_KNOWN(tmpVar != nullptr && tmpVar->getOperationType() == CGOpCode::TmpDcl, "Invalid arguments for loop indexed temporary operation");
                return createVariableName(*tmpVar);

            } else {
                // temporary variable
                var.setName(_nameGen->generateTemporary(var));
            }
        }


        return *var.getName();
    }

    virtual void printIndependentVariableName(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 0, "Invalid number of arguments for independent variable");

        _code << _nameGen->generateIndependent(op);
    }

    virtual unsigned print(const Argument<Base>& arg) {
        if (arg.getOperation() != nullptr) {
            // expression
            return printExpression(*arg.getOperation());
        } else {
            // parameter
            printParameter(*arg.getParameter());
            return 1;
        }
    }

    virtual unsigned printExpression(OperationNode<Base>& op) throw (CGException) {
        if (op.getVariableID() > 0) {
            // use variable name
            _code << createVariableName(op);
            return 1;
        } else {
            // print expression code
            return printExpressionNoVarCheck(op);
        }
    }

    virtual unsigned printExpressionNoVarCheck(OperationNode<Base>& node) throw (CGException) {
        CGOpCode op = node.getOperationType();
        switch (op) {
            case CGOpCode::ArrayCreation:
                printArrayCreationOp(node);
                break;
            case CGOpCode::SparseArrayCreation:
                printSparseArrayCreationOp(node);
                break;
            case CGOpCode::ArrayElement:
                printArrayElementOp(node);
                break;
            case CGOpCode::Assign:
                return printAssignOp(node);

            case CGOpCode::Abs:
            case CGOpCode::Acos:
            case CGOpCode::Asin:
            case CGOpCode::Atan:
            case CGOpCode::Cosh:
            case CGOpCode::Cos:
            case CGOpCode::Exp:
            case CGOpCode::Log:
            case CGOpCode::Sign:
            case CGOpCode::Sinh:
            case CGOpCode::Sin:
            case CGOpCode::Sqrt:
            case CGOpCode::Tanh:
            case CGOpCode::Tan:
                printUnaryFunction(node);
                break;
            case CGOpCode::AtomicForward: // atomicFunction.forward(q, p, vx, vy, tx, ty)
                printAtomicForwardOp(node);
                break;
            case CGOpCode::AtomicReverse: // atomicFunction.reverse(p, tx, ty, px, py)
                printAtomicReverseOp(node);
                break;
            case CGOpCode::Add:
                printOperationAdd(node);
                break;
            case CGOpCode::Alias:
                return printOperationAlias(node);

            case CGOpCode::ComLt:
            case CGOpCode::ComLe:
            case CGOpCode::ComEq:
            case CGOpCode::ComGe:
            case CGOpCode::ComGt:
            case CGOpCode::ComNe:
                printConditionalAssignment(node);
                break;
            case CGOpCode::Div:
                printOperationDiv(node);
                break;
            case CGOpCode::Inv:
                printIndependentVariableName(node);
                break;
            case CGOpCode::Mul:
                printOperationMul(node);
                break;
            case CGOpCode::Pow:
                printPowFunction(node);
                break;
            case CGOpCode::Pri:
                // do nothing
                break;
            case CGOpCode::Sub:
                printOperationMinus(node);
                break;

            case CGOpCode::UnMinus:
                printOperationUnaryMinus(node);
                break;

            case CGOpCode::DependentMultiAssign:
                return printDependentMultiAssign(node);

            case CGOpCode::Index:
                return 0; // nothing to do
            case CGOpCode::IndexAssign:
                printIndexAssign(node);
                break;
            case CGOpCode::IndexDeclaration:
                return 0; // already done

            case CGOpCode::LoopStart:
                printLoopStart(node);
                break;
            case CGOpCode::LoopIndexedIndep:
                printLoopIndexedIndep(node);
                break;
            case CGOpCode::LoopIndexedDep:
                printLoopIndexedDep(node);
                break;
            case CGOpCode::LoopIndexedTmp:
                printLoopIndexedTmp(node);
                break;
            case CGOpCode::TmpDcl:
                // nothing to do
                return 0;
            case CGOpCode::Tmp:
                printTmpVar(node);
                break;
            case CGOpCode::LoopEnd:
                printLoopEnd(node);
                break;
            case CGOpCode::IndexCondExpr:
                printIndexCondExprOp(node);
                break;
            case CGOpCode::StartIf:
                printStartIf(node);
                break;
            case CGOpCode::ElseIf:
                printElseIf(node);
                break;
            case CGOpCode::Else:
                printElse(node);
                break;
            case CGOpCode::EndIf:
                printEndIf(node);
                break;
            case CGOpCode::CondResult:
                printCondResult(node);
                break;
            default:
                std::stringstream ss;
                ss << "Unknown operation code '" << op << "'.";
                throw CGException(ss.str());
        }
        return 1;
    }

    virtual unsigned printAssignOp(OperationNode<Base>& node) throw (CGException) {
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() == 1, "Invalid number of arguments for assign operation");

        return print(node.getArguments()[0]);
    }

    virtual void printUnaryFunction(OperationNode<Base>& op) throw (CGException) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 1, "Invalid number of arguments for unary function");

        switch (op.getOperationType()) {
            case CGOpCode::Abs:
                _code << "\\abs{";
                print(op.getArguments()[0]);
                _code << "}";
                return;
            case CGOpCode::Acos:
                _code << "\\arccos";
                break;
            case CGOpCode::Asin:
                _code << "\\arcsin";
                break;
            case CGOpCode::Atan:
                _code << "\\arctan";
                break;
            case CGOpCode::Cosh:
                _code << "\\cosh";
                break;
            case CGOpCode::Cos:
                _code << "\\cos";
                break;
            case CGOpCode::Exp:
                _code << "\\exp"; ///////////////////////////////////////// consider using superscript
                break;
            case CGOpCode::Log:
                _code << "\\ln";
                break;
            case CGOpCode::Sinh:
                _code << "\\sinh";
                break;
            case CGOpCode::Sign:
                _code << "\\operatorname{sgn}";
                break;    
            case CGOpCode::Sin:
                _code << "\\sin";
                break;
            case CGOpCode::Sqrt:
                _code << "\\sqrt{";
                print(op.getArguments()[0]);
                _code << "}";
                return;
            case CGOpCode::Tanh:
                _code << "\\tanh";
                break;
            case CGOpCode::Tan:
                _code << "\\tan";
                break;
            default:
                std::stringstream ss;
                ss << "Unknown function name for operation code '" << op.getOperationType() << "'.";
                throw CGException(ss.str());
        }

        _code << "\\left\\(";
        print(op.getArguments()[0]);
        _code << "\\right\\)";
    }

    virtual void printPowFunction(OperationNode<Base>& op) throw (CGException) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 2, "Invalid number of arguments for pow() function");

        _code << "{";
        print(op.getArguments()[0]);
        _code << "}^{";
        print(op.getArguments()[1]);
        _code << "}";
    }

    virtual unsigned printOperationAlias(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 1, "Invalid number of arguments for alias");
        return print(op.getArguments()[0]);
    }

    virtual void printOperationAdd(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 2, "Invalid number of arguments for addition");

        print(op.getArguments()[0]);
        _code << " + ";
        print(op.getArguments()[1]);
    }

    virtual void printOperationMinus(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 2, "Invalid number of arguments for subtraction");

        const Argument<Base>& left = op.getArguments()[0];
        const Argument<Base>& right = op.getArguments()[1];

        bool encloseRight = encloseInParenthesesMul(right.getOperation());

        print(left);
        _code << " - ";
        if (encloseRight) {
            _code << "\\left\\(";
        }
        print(right);
        if (encloseRight) {
            _code << "\\right\\)";
        }
    }

    virtual void printOperationDiv(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 2, "Invalid number of arguments for division");

        const Argument<Base>& left = op.getArguments()[0];
        const Argument<Base>& right = op.getArguments()[1];


        _code << "\\frac{";
        print(left);
        _code << "}{";
        print(right);
        _code << "}";
        
    }

    static inline bool encloseInParenthesesMul(const OperationNode<Base>* node) {
        while (node != nullptr) {
            if (node->getVariableID() != 0)
                return false;
            else if (node->getOperationType() == CGOpCode::Alias)
                node = node->getArguments()[0].getOperation();
            else
                break;
        }
        return node != nullptr &&
                node->getVariableID() == 0 &&
                node->getOperationType() != CGOpCode::Div &&
                node->getOperationType() != CGOpCode::Mul &&
                !isFunction(node->getOperationType());
    }

    virtual void printOperationMul(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 2, "Invalid number of arguments for multiplication");

        const Argument<Base>& left = op.getArguments()[0];
        const Argument<Base>& right = op.getArguments()[1];

        bool encloseLeft = encloseInParenthesesMul(left.getOperation());
        bool encloseRight = encloseInParenthesesMul(right.getOperation());

        if (encloseLeft) {
            _code << "\\left\\(";
        }
        print(left);
        if (encloseLeft) {
            _code << "\\right\\)";
        }
        _code << " ";
        if (encloseRight) {
            _code << "\\left\\(";
        }
        print(right);
        if (encloseRight) {
            _code << "\\right\\)";
        }
    }

    virtual void printOperationUnaryMinus(OperationNode<Base>& op) {
        CPPADCG_ASSERT_KNOWN(op.getArguments().size() == 1, "Invalid number of arguments for unary minus");

        const Argument<Base>& arg = op.getArguments()[0];

        bool enclose = encloseInParenthesesMul(arg.getOperation());

        _code << "-";
        if (enclose) {
            _code << "\\left\\(";
        }
        print(arg);
        if (enclose) {
            _code << "\\right\\)";
        }
    }

    virtual void printConditionalAssignment(OperationNode<Base>& node) {
        CPPADCG_ASSERT_UNKNOWN(node.getVariableID() > 0);

        const std::vector<Argument<Base> >& args = node.getArguments();
        const Argument<Base> &left = args[0];
        const Argument<Base> &right = args[1];
        const Argument<Base> &trueCase = args[2];
        const Argument<Base> &falseCase = args[3];

        bool isDep = isDependent(node);
        const std::string& varName = createVariableName(node);

        if ((trueCase.getParameter() != nullptr && falseCase.getParameter() != nullptr && *trueCase.getParameter() == *falseCase.getParameter()) ||
                (trueCase.getOperation() != nullptr && falseCase.getOperation() != nullptr && trueCase.getOperation() == falseCase.getOperation())) {
            // true and false cases are the same
            printAssigmentStart(node, varName, isDep);
            print(trueCase);
            printAssigmentEnd(node);
        } else {
            checkEquationEnvEnd();
            
            _code << "\\eIf{";
            printEquationEnvStart();
            print(left);
            _code << " " << getComparison(node.getOperationType()) << " ";
            print(right);
            printEquationEnvEnd();
            _code << "}{" << _endline;
            //checkEquationEnvStart(); // no need
            printAssigmentStart(node, varName, isDep);
            print(trueCase);
            printAssigmentEnd(node);
            checkEquationEnvEnd();
            _code << "} {" << _endline; // else
            //checkEquationEnvStart(); // no need
            printAssigmentStart(node, varName, isDep);
            print(falseCase);
            printAssigmentEnd(node);
            checkEquationEnvEnd();
            _code << "}" << _endline; // end if
        }
    }

    inline bool isSameArgument(const Argument<Base>& newArg,
                               const Argument<Base>* oldArg) {
        if (oldArg != nullptr) {
            if (oldArg->getParameter() != nullptr) {
                if (newArg.getParameter() != nullptr) {
                    return (*newArg.getParameter() == *oldArg->getParameter());
                }
            } else {
                return (newArg.getOperation() == oldArg->getOperation());
            }
        }
        return false;
    }

    virtual void printArrayCreationOp(OperationNode<Base>& op);

    virtual void printSparseArrayCreationOp(OperationNode<Base>& op);

    inline void printArrayStructInit(const std::string& dataArrayName,
                                     size_t pos,
                                     const std::vector<OperationNode<Base>*>& arrays,
                                     size_t k);

    inline void printArrayStructInit(const std::string& dataArrayName,
                                     OperationNode<Base>& array);

    inline void markArrayChanged(OperationNode<Base>& ty);

    inline size_t printArrayCreationUsingLoop(size_t startPos,
                                              OperationNode<Base>& array,
                                              size_t startj,
                                              std::vector<const Argument<Base>*>& tmpArrayValues);

    inline std::string getTempArrayName(const OperationNode<Base>& op);

    virtual void printArrayElementOp(OperationNode<Base>& op);

    virtual void printAtomicForwardOp(OperationNode<Base>& atomicFor) {
        CPPADCG_ASSERT_KNOWN(atomicFor.getInfo().size() == 3, "Invalid number of information elements for atomic forward operation");
        int q = atomicFor.getInfo()[1];
        int p = atomicFor.getInfo()[2];
        size_t p1 = p + 1;
        const std::vector<Argument<Base> >& opArgs = atomicFor.getArguments();
        CPPADCG_ASSERT_KNOWN(opArgs.size() == p1 * 2, "Invalid number of arguments for atomic forward operation");

        size_t id = atomicFor.getInfo()[0];
        std::vector<OperationNode<Base>*> tx(p1), ty(p1);
        for (size_t k = 0; k < p1; k++) {
            tx[k] = opArgs[0 * p1 + k].getOperation();
            ty[k] = opArgs[1 * p1 + k].getOperation();
        }

        CPPADCG_ASSERT_KNOWN(tx[0]->getOperationType() == CGOpCode::ArrayCreation, "Invalid array type");
        CPPADCG_ASSERT_KNOWN(p == 0 || tx[1]->getOperationType() == CGOpCode::SparseArrayCreation, "Invalid array type");
        CPPADCG_ASSERT_KNOWN(ty[p]->getOperationType() == CGOpCode::ArrayCreation, "Invalid array type");

        // tx
        for (size_t k = 0; k < p1; k++) {
            printArrayStructInit(_ATOMIC_TX, k, tx, k);
        }
        // ty
        printArrayStructInit(_ATOMIC_TY, *ty[p]);
        _ss.str("");

        _code << _starteq 
                << (*_info)->atomicFunctionId2Name.at(id) << ".forward("
                << q << ", " << p << ", "
                << _ATOMIC_TX << ", &" << _ATOMIC_TY << ")"
                << _endeq << _endline;

        /**
         * the values of ty are now changed
         */
        markArrayChanged(*ty[p]);
    }

    virtual void printAtomicReverseOp(OperationNode<Base>& atomicRev) {
        CPPADCG_ASSERT_KNOWN(atomicRev.getInfo().size() == 2, "Invalid number of information elements for atomic reverse operation");
        int p = atomicRev.getInfo()[1];
        size_t p1 = p + 1;
        const std::vector<Argument<Base> >& opArgs = atomicRev.getArguments();
        CPPADCG_ASSERT_KNOWN(opArgs.size() == p1 * 4, "Invalid number of arguments for atomic reverse operation");

        size_t id = atomicRev.getInfo()[0];
        std::vector<OperationNode<Base>*> tx(p1), px(p1), py(p1);
        for (size_t k = 0; k < p1; k++) {
            tx[k] = opArgs[0 * p1 + k].getOperation();
            px[k] = opArgs[2 * p1 + k].getOperation();
            py[k] = opArgs[3 * p1 + k].getOperation();
        }

        CPPADCG_ASSERT_KNOWN(tx[0]->getOperationType() == CGOpCode::ArrayCreation, "Invalid array type");
        CPPADCG_ASSERT_KNOWN(p == 0 || tx[1]->getOperationType() == CGOpCode::SparseArrayCreation, "Invalid array type");

        CPPADCG_ASSERT_KNOWN(px[0]->getOperationType() == CGOpCode::ArrayCreation, "Invalid array type");

        CPPADCG_ASSERT_KNOWN(py[0]->getOperationType() == CGOpCode::SparseArrayCreation, "Invalid array type");
        CPPADCG_ASSERT_KNOWN(p == 0 || py[1]->getOperationType() == CGOpCode::ArrayCreation, "Invalid array type");

        // tx
        for (size_t k = 0; k < p1; k++) {
            printArrayStructInit(_ATOMIC_TX, k, tx, k);
        }
        // py
        for (size_t k = 0; k < p1; k++) {
            printArrayStructInit(_ATOMIC_PY, k, py, k);
        }
        // px
        printArrayStructInit(_ATOMIC_PX, *px[0]);
        _ss.str("");

        _code << _starteq 
                << (*_info)->atomicFunctionId2Name.at(id) << ".reverse("
                << p << ", "
                << _ATOMIC_TX << ", &" << _ATOMIC_PX << ", " << _ATOMIC_PY << ")"
                << _endeq << _endline;

        /**
         * the values of px are now changed
         */
        markArrayChanged(*px[0]);
    }

    virtual unsigned printDependentMultiAssign(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::DependentMultiAssign, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() > 0, "Invalid number of arguments");

        const std::vector<Argument<Base> >& args = node.getArguments();
        for (size_t a = 0; a < args.size(); a++) {
            bool useArg = false;
            const Argument<Base>& arg = args[a];
            if (arg.getParameter() != nullptr) {
                useArg = true;
            } else {
                CGOpCode op = arg.getOperation()->getOperationType();
                useArg = op != CGOpCode::DependentRefRhs && op != CGOpCode::LoopEnd && op != CGOpCode::EndIf;
            }

            if (useArg) {
                printAssigment(node, arg); // ignore other arguments!
                return 1;
            }
        }
        return 0;
    }

    virtual void printLoopStart(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::LoopStart, "Invalid node type");

        LoopStartOperationNode<Base>& lnode = static_cast<LoopStartOperationNode<Base>&> (node);
        _currentLoops.push_back(&lnode);

        const std::string& jj = *lnode.getIndex().getName();
        std::string lastIt;
        if (lnode.getIterationCountNode() != nullptr) {
            lastIt = *lnode.getIterationCountNode()->getIndex().getName() + " - 1";
        } else {
            std::ostringstream oss;
            oss << (lnode.getIterationCount()-1);
            lastIt = oss.str();
        }

        checkEquationEnvEnd();
        
        _code <<  "\\For{$" << jj << " = 0$ " << jj << " \\KwTo " << lastIt << "} {" << _endline;
    }

    virtual void printLoopEnd(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::LoopEnd, "Invalid node type");

        checkEquationEnvEnd();
        
        _code << "}" << _endline;

        _currentLoops.pop_back();
    }

    virtual void printLoopIndexedDep(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() >= 1, "Invalid number of arguments for loop indexed dependent operation");

        // LoopIndexedDep
        print(node.getArguments()[0]);
    }

    virtual void printLoopIndexedIndep(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::LoopIndexedIndep, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getInfo().size() == 1, "Invalid number of information elements for loop indexed independent operation");

        // CGLoopIndexedIndepOp
        size_t pos = node.getInfo()[1];
        const IndexPattern* ip = (*_info)->loopIndependentIndexPatterns[pos];
        _code << _nameGen->generateIndexedIndependent(node, *ip);
    }

    virtual void printLoopIndexedTmp(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::LoopIndexedTmp, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() == 2, "Invalid number of arguments for loop indexed temporary operation");
        OperationNode<Base>* tmpVar = node.getArguments()[0].getOperation();
        CPPADCG_ASSERT_KNOWN(tmpVar != nullptr && tmpVar->getOperationType() == CGOpCode::TmpDcl, "Invalid arguments for loop indexed temporary operation");

        print(node.getArguments()[1]);
    }

    virtual void printTmpVar(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::Tmp, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() > 0, "Invalid number of arguments for temporary variable usage operation");
        OperationNode<Base>* tmpVar = node.getArguments()[0].getOperation();
        CPPADCG_ASSERT_KNOWN(tmpVar != nullptr && tmpVar->getOperationType() == CGOpCode::TmpDcl, "Invalid arguments for loop indexed temporary operation");

        _code << *tmpVar->getName();
    }

    virtual void printIndexAssign(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::IndexAssign, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() > 0, "Invalid number of arguments for an index assignment operation");

        IndexAssignOperationNode<Base>& inode = static_cast<IndexAssignOperationNode<Base>&> (node);

        checkEquationEnvStart();
        
        const IndexPattern& ip = inode.getIndexPattern();
        _code << _starteq
                << (*inode.getIndex().getName())
                << " = " << indexPattern2String(ip, inode.getIndexPatternIndexes()) << _endeq << _endline;
    }

    virtual void printIndexCondExprOp(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::IndexCondExpr, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() == 1, "Invalid number of arguments for an index condition expression operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[0].getOperation() != nullptr, "Invalid argument for an index condition expression operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[0].getOperation()->getOperationType() == CGOpCode::Index, "Invalid argument for an index condition expression operation");

        const std::vector<size_t>& info = node.getInfo();

        IndexOperationNode<Base>& iterationIndexOp = static_cast<IndexOperationNode<Base>&> (*node.getArguments()[0].getOperation());
        const std::string& index = *iterationIndexOp.getIndex().getName();

        checkEquationEnvStart();
        
        printIndexCondExpr(_code, info, index);
    }

    virtual void printStartIf(OperationNode<Base>& node) {
        /**
         * the first argument is the condition, following arguments are
         * just extra dependencies that must be defined outside the if
         */
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::StartIf, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() >= 1, "Invalid number of arguments for an 'if start' operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[0].getOperation() != nullptr, "Invalid argument for an 'if start' operation");

        checkEquationEnvEnd();
        
        _code << "\\uIf{";
        //checkEquationEnvStart(); // no need
        printIndexCondExprOp(*node.getArguments()[0].getOperation());
        checkEquationEnvEnd();
        _code << "} {" << _endline;
    }

    virtual void printElseIf(OperationNode<Base>& node) {
        /**
         * the first argument is the condition, the second argument is the 
         * if start node, the following arguments are assignments in the
         * previous if branch
         */
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::ElseIf, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() >= 2, "Invalid number of arguments for an 'else if' operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[0].getOperation() != nullptr, "Invalid argument for an 'else if' operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[1].getOperation() != nullptr, "Invalid argument for an 'else if' operation");

        checkEquationEnvEnd();
        
        _code << "} \\uElseIf {";
        //checkEquationEnvStart(); // no need
        printIndexCondExprOp(*node.getArguments()[1].getOperation());
        checkEquationEnvEnd();
        _code << "} {" << _endline;
    }

    virtual void printElse(OperationNode<Base>& node) {
        /**
         * the first argument is the  if start node, the following arguments
         * are assignments in the previous if branch
         */
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::Else, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() >= 1, "Invalid number of arguments for an 'else' operation");

        checkEquationEnvEnd();
        
        _code <<  "} \\Else {" << _endline;
    }

    virtual void printEndIf(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::EndIf, "Invalid node type for an 'end if' operation");

        _code << "}" << _endline;
    }

    virtual void printCondResult(OperationNode<Base>& node) {
        CPPADCG_ASSERT_KNOWN(node.getOperationType() == CGOpCode::CondResult, "Invalid node type");
        CPPADCG_ASSERT_KNOWN(node.getArguments().size() == 2, "Invalid number of arguments for an assignment inside an if/else operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[0].getOperation() != nullptr, "Invalid argument for an an assignment inside an if/else operation");
        CPPADCG_ASSERT_KNOWN(node.getArguments()[1].getOperation() != nullptr, "Invalid argument for an an assignment inside an if/else operation");

        // just follow the argument
        OperationNode<Base>& nodeArg = *node.getArguments()[1].getOperation();
        printAssigment(nodeArg);
    }

    inline bool isDependent(const OperationNode<Base>& arg) const {
        if (arg.getOperationType() == CGOpCode::LoopIndexedDep) {
            return true;
        }
        size_t id = arg.getVariableID();
        return id > _independentSize && id < _minTemporaryVarID;
    }

    virtual void printParameter(const Base& value) {
        // make sure all digits of floating point values are printed
        std::ostringstream os;
        os << std::setprecision(_parameterPrecision) << value;

        std::string number = os.str();
        size_t pos = number.find('e');
        if (pos != std::string::npos) {
            std::string n = " \\times 10^{";
            number.replace(pos, 1, n);
            pos += n.size();
            if(number[pos] == '-' || number[pos] == '+')
                pos++;
            while(number[pos] == '0')
                number.replace(pos, 1, ""); // remove zeros
                
            number += "}";
        }
        _code << number;
        
    }

    virtual const std::string& getComparison(enum CGOpCode op) const {
        switch (op) {
            case CGOpCode::ComLt:
                return _COMP_OP_LT;

            case CGOpCode::ComLe:
                return _COMP_OP_LE;

            case CGOpCode::ComEq:
                return _COMP_OP_EQ;

            case CGOpCode::ComGe:
                return _COMP_OP_GE;

            case CGOpCode::ComGt:
                return _COMP_OP_GT;

            case CGOpCode::ComNe:
                return _COMP_OP_NE;

            default:
                CPPAD_ASSERT_UNKNOWN(0);
        }
        throw CGException("Invalid comparison operator code"); // should never get here
    }

    inline const std::string& getPrintfBaseFormat() {
        static const std::string format; // empty string
        return format;
    }

    static bool isFunction(enum CGOpCode op) {
        return isUnaryFunction(op) || op == CGOpCode::Pow;
    }

    static bool isUnaryFunction(enum CGOpCode op) {
        switch (op) {
            case CGOpCode::Abs:
            case CGOpCode::Acos:
            case CGOpCode::Asin:
            case CGOpCode::Atan:
            case CGOpCode::Cosh:
            case CGOpCode::Cos:
            case CGOpCode::Exp:
            case CGOpCode::Log:
            case CGOpCode::Sign:
            case CGOpCode::Sinh:
            case CGOpCode::Sin:
            case CGOpCode::Sqrt:
            case CGOpCode::Tanh:
            case CGOpCode::Tan:
                return true;
            default:
                return false;
        }
    }

    static bool isCondAssign(enum CGOpCode op) {
        switch (op) {
            case CGOpCode::ComLt:
            case CGOpCode::ComLe:
            case CGOpCode::ComEq:
            case CGOpCode::ComGe:
            case CGOpCode::ComGt:
            case CGOpCode::ComNe:
                return true;
            default:
                return false;
        }
    }
};

template<class Base>
const std::string LanguageLatex<Base>::_COMP_OP_LT = "<";
template<class Base>
const std::string LanguageLatex<Base>::_COMP_OP_LE = "\\le";
template<class Base>
const std::string LanguageLatex<Base>::_COMP_OP_EQ = "==";
template<class Base>
const std::string LanguageLatex<Base>::_COMP_OP_GE = "\\ge";
template<class Base>
const std::string LanguageLatex<Base>::_COMP_OP_GT = ">";
template<class Base>
const std::string LanguageLatex<Base>::_COMP_OP_NE = "\\ne";

template<class Base>
const std::string LanguageLatex<Base>::_C_STATIC_INDEX_ARRAY = "index";

template<class Base>
const std::string LanguageLatex<Base>::_C_SPARSE_INDEX_ARRAY = "idx";

template<class Base>
const std::string LanguageLatex<Base>::_ATOMIC_TX = "atx";

template<class Base>
const std::string LanguageLatex<Base>::_ATOMIC_TY = "aty";

template<class Base>
const std::string LanguageLatex<Base>::_ATOMIC_PX = "apx";

template<class Base>
const std::string LanguageLatex<Base>::_ATOMIC_PY = "apy";

} // END cg namespace
} // END CppAD namespace

#endif