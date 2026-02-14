window.questionsData =[
  {
    id: 1,
    text: "If the equation x² + ax + b = 0 has roots α and β, then the value of (1 + α + α²)(1 + β + β²) is",
    options: {
      A: "α² + β² − αβ − a − b",
      B: "α² + β² − αβ − a − b − 1",
      C: "α² + β² − αβ − a − b + 1",
      D: "α² + β² + αβ − a − b + 1"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using α + β = −a and αβ = b, expanding (1 + α + α²)(1 + β + β²) and simplifying gives α² + β² − αβ − a − b + 1."
  },
  {
    id: 2,
    text: "The number of distinct real roots of x⁴ − 4x + 1 = 0 is",
    options: {
      A: "4",
      B: "2",
      C: "1",
      D: "0"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Let f(x) = x⁴ − 4x + 1. Using derivative and graph analysis, the curve cuts the x-axis at two points. Hence, there are two distinct real roots."
  },
  {
    id: 3,
    text: "If α, β ∈ R are such that 1 − 2i is a root of z² + az + β = 0, then (a − β) is equal to",
    options: {
      A: "7",
      B: "−3",
      C: "3",
      D: "−7"
    },
    correctAnswer: "D",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Since coefficients are real, 1 + 2i is also a root. Comparing coefficients gives a = −2 and β = 5. Hence, a − β = −7."
  },
  {
    id: 4,
    text: "One common factor of x² + 2x − 15, x² − 8x + 15 and x² + 7x − 30 is",
    options: {
      A: "x + 3",
      B: "x − 3",
      C: "x + 5",
      D: "x − 5"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Factorising each polynomial shows (x − 3) is common to all three expressions."
  },
  {
    id: 5,
    text: "If α and β are the roots of the equation x² + x + 1 = 0, then the value of [[1 β],[α α]] × [[α β],[1 β]] is",
    options: {
      A: "[[-1 −1],[-1 2]]",
      B: "[[1 2],[2 1]]",
      C: "[[-1 −1],[-1 −2]]",
      D: "[[1 1],[1 2]]"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using roots of unity properties α = ω, β = ω² and matrix multiplication, the resulting matrix simplifies to [[−1 −1], [−1 2]]."
  },
  {
    id: 6,
    text: "The sum of all the real roots of the equation (e²ˣ − 4)(6e²ˣ − 5eˣ + 1) = 0 is",
    options: {
      A: "logₑ3",
      B: "−logₑ3",
      C: "logₑ6",
      D: "−logₑ6"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Solving e²ˣ = 4 and 6e²ˣ − 5eˣ + 1 = 0 gives roots ln2, ln(1/3), and −ln2. Their sum equals −ln3."
  },
  {
    id: 7,
    text: "The minimum value of the sum of the squares of the roots of x² + (3 − a)x + 1 − 2a = 0 is",
    options: {
      A: "4",
      B: "5",
      C: "6",
      D: "8"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Let roots be α and β. Then α² + β² = (α + β)² − 2αβ. Minimising with respect to a gives minimum value 6."
  },
  {
    id: 8,
    text: "If α, β are the roots of x² − x − 1 = 0 and Sₙ = 2023αⁿ + 2024βⁿ, then which of the following is correct?",
    options: {
      A: "2S₁₂ = S₁₁ + S₁₀",
      B: "S₁₂ = S₁₁ + S₁₀",
      C: "2S₁₁ = S₁₂ + S₁₀",
      D: "S₁₁ = S₁₀ + S₁₂"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using recurrence relation from the quadratic equation gives Sₙ = Sₙ₋₁ + Sₙ₋₂. Hence, S₁₂ = S₁₁ + S₁₀."
  },
  {
    id: 9,
    text: "Consider the quadratic equation ax² + bx + c = 0, where a ≠ 0 and the roots are real and unequal. If the product of the roots is 40 and the sum of the roots is 14, find the quadratic equation.",
    options: {
      A: "x² − 14x + 40 = 0",
      B: "x² + 14x + 40 = 0",
      C: "x² − 14x + 50 = 0",
      D: "x² − 41x + 40 = 0"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using sum = −b/a = 14 and product = c/a = 40 gives the equation x² − 14x + 40 = 0."
  },
  {
  id: 10,
  text: "Consider the quadratic equation ax² + bx + c = 0, where a ≠ 0 and the roots are real and unequal. If one root of the equation is twice the other, and the sum of the roots is 18, find the value of the product of the roots.",
  options: {
    A: "74",
    B: "72",
    C: "84",
    D: "82"
  },
  correctAnswer: "B",
  marks: 2.5,
  negMarks: -0.833,
  solution: "Let the roots be α and 2α. Then α + 2α = 3α = 18, so α = 6. Product of roots = α·2α = 2α² = 2×36 = 72."
 }

];
