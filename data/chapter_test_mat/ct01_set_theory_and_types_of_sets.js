window.questionsData =[
  {
    id: 1,
    text: "If X = {a, b, c, d} and Y = {f, b, d, g}, find X ∩ Y.",
    options: {
      A: "{a, c}",
      B: "{g, f}",
      C: "{a, b, c, d, g, f}",
      D: "{b, d}"
    },
    correctAnswer: "D",
    marks: 2.5,
    negMarks: -0.833,
    solution: "The intersection of two sets consists of elements common to both sets. Common elements in X and Y are b and d. Hence, X ∩ Y = {b, d}."
  },
  {
    id: 2,
    text: "If A, B, C be three sets such that A ∪ B = A ∪ C and A ∩ B = A ∩ C, then",
    options: {
      A: "A = B",
      B: "B = C",
      C: "A = C",
      D: "A = B = C"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Given A ∪ B = A ∪ C and A ∩ B = A ∩ C. These two conditions together imply that the parts of B and C outside A are identical. Hence, B = C."
  },
  {
    id: 3,
    text: "Let A = {1, 2, 3}. Consider the relation R = {(1,1), (2,2), (3,3), (1,2), (2,3), (1,3)}. Then R is",
    options: {
      A: "reflexive only",
      B: "reflexive and transitive",
      C: "symmetric and transitive",
      D: "neither symmetric nor transitive"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Since (1,1), (2,2), and (3,3) are present, the relation is reflexive. Also, (1,2) and (2,3) imply (1,3), which is present, so the relation is transitive."
  },
  {
    id: 4,
    text: "In a class of 105 students, each studies at least one of the subjects Mathematics, Physics and Chemistry. In Mathematics 47, in Physics 50, and in Chemistry 52 students study. 16 study Mathematics and Physics, 17 Mathematics and Chemistry and 16 Physics and Chemistry. What will be the number of students who study all the three subjects?",
    options: {
      A: "5",
      B: "6",
      C: "7",
      D: "4"
    },
    correctAnswer: "A",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using inclusion–exclusion principle: 105 = 47 + 50 + 52 − (16 + 17 + 16) + x. Solving gives x = 5."
  },
  {
    id: 5,
    text: "If the Cartesian product of two sets A and B (A × B) = {(3,2), (3,4), (5,2), (5,4)}, find set A.",
    options: {
      A: "{3,2}",
      B: "{3,4}",
      C: "{3,5}",
      D: "{3,3}"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "In A × B, the first element of each ordered pair belongs to set A. The first elements are 3 and 5. Hence, A = {3, 5}."
  },
  {
    id: 6,
    text: "Consider the following statements:\n1. If P = {m, n} and Q = {n, m}, then P × Q = {(m, n), (n, m)}.\n2. If A and B are non-empty sets, then A × B is a non-empty set of ordered pairs (x, y) such that x ∈ A and y ∈ B.\n3. If A = {1, 2}, B = {3, 4}, then A × (B ∩ Φ) = Φ.\nWhich of the above statements is/are correct?",
    options: {
      A: "1 and 2 only",
      B: "2 and 3 only",
      C: "1 and 3 only",
      D: "1, 2 and 3"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Statement 1 is false as P × Q has four ordered pairs. Statements 2 and 3 are true. Hence, statements 2 and 3 are correct."
  },
  {
    id: 7,
    text: "Let A = {(x, y) ∈ R × R | 2x² + 2y² − 2x − 2y = 1}, B = {(x, y) ∈ R × R | 4x² + 4y² − 16x + 7 = 0}, C = {(x, y) ∈ R × R | x² + y² − 4x − 2y + 5 ≤ r²}. The minimum value of |r| such that A ∪ B ⊆ C is equal to:",
    options: {
      A: "(3 + √10) / 2",
      B: "(2 + √10) / 2",
      C: "(3 + 2√5) / 2",
      D: "1 + √5"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "By converting equations into standard circle forms and comparing radii, the minimum value of |r| is found to be (3 + 2√5) / 2."
  },
  {
    id: 8,
    text: "Consider the following statements:\n1. A = (A ∪ B) ∪ (A − B)\n2. A ∪ (B − A) = (A ∪ B)\n3. B = (A ∪ B) − (A − B)\nWhich of the statements given above are correct?",
    options: {
      A: "1 and 2 only",
      B: "2 and 3 only",
      C: "1 and 3 only",
      D: "None of the above"
    },
    correctAnswer: "B",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Statement 1 is incorrect. Statements 2 and 3 are correct using set identities."
  },
  {
    id: 9,
    text: "Out of 80 players, 35 play cricket, 42 play hockey, 25 play football, 8 play both cricket and hockey, 10 play both cricket and football, 7 play both hockey and football, 3 play all the three games. How many players are playing only one game?",
    options: {
      A: "102",
      B: "80",
      C: "61",
      D: "63"
    },
    correctAnswer: "C",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Using inclusion–exclusion principle, players playing only one game = 61."
  },
  {
    id: 10,
    text: "Out of 80 players, 35 play cricket, 42 play hockey, 25 play football, 8 play both cricket and hockey, 10 play both cricket and football, 7 play both hockey and football, 3 play all the three games. How many players play exactly two games?",
    options: {
      A: "19",
      B: "61",
      C: "80",
      D: "16"
    },
    correctAnswer: "D",
    marks: 2.5,
    negMarks: -0.833,
    solution: "Players playing exactly two games = (8 + 10 + 7) − 2×3 = 16."
  }
];
