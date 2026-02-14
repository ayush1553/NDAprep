window.questionsData = [
  {
    id: 1,
    text: "If A = {0, 1, 2, 3, 4} and B = {1, 2, 4, 8} such that R is a relation from A to B such that R = {(x, y) : x ∈ A, y ∈ B and y = 2^x}, then find the domain of R.",
    options: {
      A: "{0, 1, 2}",
      B: "{0, 1, 2, 3}",
      C: "{0, 1, 2, 4}",
      D: "None of these"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "The domain of a relation consists of first elements of ordered pairs. Here R = {(0,1), (1,2), (2,4), (3,8)}. Hence, Domain(R) = {0, 1, 2, 3}."
  },
  {
    id: 2,
    text: "If 2f(x) + f(1/x) = log x for all x > 0, then f(e^x) is",
    options: {
      A: "x^2",
      B: "x",
      C: "2x",
      D: "x/2"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Replacing x by 1/x and solving the system gives f(x) = (2logx − log(1/x))/3. Substituting x = e^x gives f(e^x) = x."
  },
  {
    id: 3,
    text: "Let A = {−2, −1, 0, 1, 2, 3}. Let R be a relation on A defined by xRy if and only if y = max{x, 1}. Let l be the number of elements in R. Let m and n be the minimum number of elements required to be added in R to make it reflexive and symmetric respectively. Then l + m + n is equal to",
    options: {
      A: "12",
      B: "11",
      C: "13",
      D: "14"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "R = {(-2,1), (-1,1), (0,1), (1,1), (2,2), (3,3)} so l = 6. Missing reflexive pairs = 3, missing symmetric pairs = 3. Hence l + m + n = 6 + 3 + 3 = 12."
  },
  {
    id: 4,
    text: "If A = {1, 2, 3, ..., 14} and R is a relation defined on A such that R = {(x, y) : 3x − y = 0 where x, y ∈ A}, then find the range of R.",
    options: {
      A: "{3, 6, 9, 12}",
      B: "{1, 3, 6, 9, 12}",
      C: "{6, 9, 12}",
      D: "None of these"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "For x ∈ A, y = 3x must belong to A. Valid values are y = 3, 6, 9, 12. Hence, Range(R) = {3, 6, 9, 12}."
  },
  {
    id: 5,
    text: "If R and S are two non-void relations on a set A. 1. If R and S are transitive ⇒ R ∪ S is transitive. 2. If R and S are reflexive ⇒ R ∩ S is reflexive. Which of the above statements is/are correct?",
    options: {
      A: "1 only",
      B: "2 only",
      C: "Both 1 and 2",
      D: "Neither 1 nor 2"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Union of two transitive relations need not be transitive. Intersection of two reflexive relations is always reflexive. Hence, only statement 2 is correct."
  },
  {
    id: 6,
    text: "If functions f and g are defined as f : [0, π/2] → R, f(x) = sin x and g : [0, π/2] → R, g(x) = cos x then ______.",
    options: {
      A: "f + g is one-one and fg is not one-one",
      B: "f + g is not one-one and fg is one-one",
      C: "f + g is not one-one and fg is not one-one",
      D: "f + g is one-one and fg is one-one"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "f + g = sin x + cos x gives same values for x = 0 and x = π/2, so not one-one. fg = sin x cos x = (1/2)sin2x is also not one-one on [0, π/2]."
  },
  {
    id: 7,
    text: "Let f : R − {3/5} → R be defined by f(x) = (3x + 2)/(5x − 3). Then",
    options: {
      A: "f⁻¹(x) = f(x)",
      B: "f⁻¹(x) = −f(x)",
      C: "(f ∘ f)(x) = −x",
      D: "f⁻¹(x) = (1/19)f(x)"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Solving y = (3x + 2)/(5x − 3) for x gives x = (3y + 2)/(5y − 3). Hence, f⁻¹(x) = f(x)."
  },
  {
    id: 8,
    text: "If [x]^2 − 5[x] + 6 = 0, where [ ] denotes the greatest integer function, then",
    options: {
      A: "x ∈ [3, 4]",
      B: "x ∈ (2, 3]",
      C: "x ∈ [2, 3]",
      D: "x ∈ [2, 4]"
    },
    correctAnswer: "D",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Let [x] = k. Then k² − 5k + 6 = 0 ⇒ k = 2 or 3. Hence x ∈ [2,3) ∪ [3,4) = [2,4)."
  },
  {
    id: 9,
    text: "Let a function f be defined on R − {0} and f(x) + 3f(1/x) = 2x + 5. If f is differentiable, then what is f′(0.5) equal to?",
    options: {
      A: "1",
      B: "2.5",
      C: "0",
      D: "-3.25"
    },
    correctAnswer: "D",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using substitution and elimination, f(x) = (2x − 6/x + 10)/8. Differentiating gives f′(x) = (2 + 6/x²)/8. Substituting x = 0.5 gives f′(0.5) = −3.25."
  },
  {
  id: 10,
  text: "Let a function f be defined on R − {0} and f(x) + 3f(1/x) = 2x + 5. What is f(1) equal to?",
  options: {
    A: "23/4",
    B: "2",
    C: "7/4",
    D: "7/2"
  },
  correctAnswer: "C",
  marks: 2.5,
  negMarks: -0.833,
  solution: "Given f(x) + 3f(1/x) = 2x + 5. Replacing x by 1/x gives f(1/x) + 3f(x) = 2/x + 5. Subtracting three times the second equation from the first gives −8f(x) = 2x − 6/x − 10. Hence, 8f(x) = −2x + 6/x + 10. Putting x = 1 gives 8f(1) = 14, so f(1) = 7/4."
}

];
