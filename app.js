const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});