// [Subject] [Year] [Session] Questions Data Template
// Save this file as: data/questions/[Subject]_[Year]_[Session].js
// Example: data/questions/Mathematics_2023_1.js

window.questionsData = [
    {
        id: 1,
        text: "Question text goes here...",
        options: {
            A: "Option A",
            B: "Option B",
            C: "Option C",
            D: "Option D"
        },
        correctAnswer: "A", // Must be A, B, C, or D
        marks: 2.5, // Standard NDA marks (2.5 for Math, 4.0 for GAT)
        negMarks: 0.83 // Negative marks (0.83 for Math, 1.33 for GAT)
    },
    // Add more questions here...
];
