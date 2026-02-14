---
description: How to add a new Previous Year Question (PYQ) data set
---

Follow these steps to add a new PYQ to the platform:

1.  **Create the Data File**:
    - Go to the `data/questions/` directory.
    - Create a new file named `[Subject]_[Year]_[Session].js`.
    - Example: `Mathematics_2023_1.js`.
    - Use the following template:
      ```javascript
      window.questionsData = [
          {
              id: 1,
              text: "Your question text here...",
              options: { A: "Option 1", B: "Option 2", C: "Option 3", D: "Option 4" },
              correctAnswer: "A",
              marks: 2.5,
              negMarks: 0.83
          },
          // Add more questions...
      ];
      ```

2.  **Enable the Test in the UI**:
    - Open `pyq-years.html`.
    - Locate the `checkAvailability` function (near the end of the file).
    - Update the `isAvailable` constant to include your new test.
    - Example:
      ```javascript
      const isAvailable = (subject === 'Mathematics' && year === '2022' && session === '2') ||
                          (subject === 'Mathematics' && year === '2025' && session === '2') ||
                          (subject === 'Mathematics' && year === '2023' && session === '1'); // Add this line
      ```

3.  **Verify**:
    - Open the app in your browser.
    - Navigate to the PYQ section for the corresponding subject.
    - Ensure the "Coming Soon" button has turned into "Start Test" for the new year/session.
    - Click it to verify questions load correctly.
