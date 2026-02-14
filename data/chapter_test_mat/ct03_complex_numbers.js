window.questionsData =[
  {
    id: 1,
    text: "If z = 2i + 1, find the value of |(z + z̄ + 1)/(z + z̄ − 1)|, where z̄ is the conjugate of the complex number z.",
    options: {
      A: "1",
      B: "2",
      C: "3",
      D: "4"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "z = 1 + 2i, z̄ = 1 − 2i. Then z + z̄ = 2. Expression becomes |(2 + 1)/(2 − 1)| = |3| = 3."
  },
  {
    id: 2,
    text: "The value of arg((1 + √3i)(√3 + i)/(1 + i)) will be:",
    options: {
      A: "π/2",
      B: "π/3",
      C: "π/4",
      D: "π/6"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using properties of argument: arg(z1z2/z3) = arg(z1)+arg(z2)−arg(z3). Substituting values gives θ = π/4."
  },
  {
    id: 3,
    text: "If (z − 1)/(z + 1) is a purely imaginary number, then z z̄ is equal to",
    options: {
      A: "0",
      B: "1",
      C: "2",
      D: "None of these"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Let z = x + iy. Since the given expression is purely imaginary, its real part is zero, giving x² + y² = 1. Hence, z z̄ = 1."
  },
  {
    id: 4,
    text: "Evaluate the expression ((√2 + i√2)/2)^64",
    options: {
      A: "e^{i16π}",
      B: "−e^{iπ/16}",
      C: "e^{i8π}",
      D: "−e^{iπ/8}"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "The given complex number equals cos(π/4)+i sin(π/4). Raising to power 64 gives e^{i16π}."
  },
  {
    id: 5,
    text: "The argument of the complex number (i/2 − 2/i) is equal to",
    options: {
      A: "π/4",
      B: "3π/4",
      C: "π/12",
      D: "π/2"
    },
    correctAnswer: "D",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Simplifying gives z = (5i)/2 which lies on the positive imaginary axis. Hence, arg(z) = π/2."
  },
  {
    id: 6,
    text: "For two non-zero complex numbers z₁ and z₂, if Re(z₁z₂) = 0 and Re(z₁ + z₂) = 0, then which of the following are possible?",
    options: {
      A: "Im(z₁) > 0 and Im(z₂) > 0",
      B: "Im(z₁) < 0 and Im(z₂) > 0",
      C: "Im(z₁) > 0 and Im(z₂) < 0",
      D: "Im(z₁) < 0 and Im(z₂) < 0"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "From given conditions, imaginary parts must be of opposite signs. Hence, options B and C are correct → option B."
  },
  {
    id: 7,
    text: "Among the statements: (S1) The set {z ∈ C − {−i} : |z| = 1 and (z − i)/(z + i) is purely real} contains exactly two elements. (S2) The set {z ∈ C − {−1} : |z| = 1 and (z − 1)/(z + 1) is purely imaginary} contains infinitely many elements.",
    options: {
      A: "both are incorrect",
      B: "only (S1) is correct",
      C: "only (S2) is correct",
      D: "both are correct"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "S1 gives no valid solution on the unit circle. S2 holds for infinitely many points on unit circle. Hence, only S2 is correct."
  },
  {
    id: 8,
    text: "Let α be a solution of x² + x + 1 = 0, and for some real b and a given determinant expression equals zero. If 4/α⁴ + m/α⁶ + n/α⁸ = 3, then m + n is equal to",
    options: {
      A: "3",
      B: "11",
      C: "7",
      D: "8"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using properties of roots of unity and simplifying the determinant condition gives m + n = 11."
  },
  {
  id: 9,
  text: "If z₁ = (√3 + i)/(√3 − i) and z₂ = i(√3 + i)^4 / (2 − i2√3)^2, then which of the following is correct?",
  options: {
    A: "|z₁| < |z₂|",
    B: "|z₁| > |z₂|",
    C: "|z₁| ≥ |z₂|",
    D: "None of these"
  },
  correctAnswer: "D",
  marks: 2.5,
  negMarks: -0.833,
  solution: "Using properties of modulus: |z₁| = |(√3 + i)/(√3 − i)| = 1 and |z₂| = |i|( |√3 + i|^4 ) / |2 − i2√3|^2 = 1. Hence |z₁| = |z₂|, so none of the given inequalities is true."
 },
 {
  id: 10,
  text: "If z₁ = (√3 + i)/(√3 − i) and z₂ = i(√3 + i)^4 / (2 − i2√3)^2, then amp(z₁) + amp(z₂) is equal to",
  options: {
    A: "π/3",
    B: "π/6",
    C: "π/9",
    D: "−π/6"
  },
  correctAnswer: "B",
  marks: 2.5,
  negMarks: -0.833,
  solution: "amp(z₁) = amp(√3 + i) − amp(√3 − i) = π/6 − (−π/6) = π/3. amp(z₂) = amp(i) + 4amp(√3 + i) − 2amp(2 − i2√3) = π/2 + 4(π/6) − 2(−π/3) = 11π/6. Reducing to principal value gives −π/6. Hence amp(z₁) + amp(z₂) = π/3 − π/6 = π/6."
}


];
