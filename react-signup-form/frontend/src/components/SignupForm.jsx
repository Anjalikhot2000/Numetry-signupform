import { useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import "./SignupForm.css"; // Reuse existing styles

const SignupForm = () => {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
    photo: null, // File input
  });

  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState({
    password: false,
    confirmPassword: false,
  });

  // Backend URLs
  const PRIMARY_API_URL = "https://numetry-signupform-backend.vercel.app";
  const FALLBACK_API_URL = "http://localhost:5000/api/signup";

  const handleChange = (e) => {
    const { name, value } = e.target;

    if (name === "photo") {
      setFormData({ ...formData, photo: e.target.files[0] });
    } else {
      setFormData({ ...formData, [name]: value });
    }
    setError(""); // Clear error when the user types
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Check if passwords match
    if (formData.password !== formData.confirmPassword) {
      return setError("Passwords do not match.");
    }

    // Prepare form data for file upload
    const signupData = new FormData();
    signupData.append("name", formData.name);
    signupData.append("email", formData.email);
    signupData.append("password", formData.password);
    signupData.append("photo", formData.photo);

    try {
      // Attempt to submit data to the primary API URL
      const response = await axios.post(PRIMARY_API_URL, signupData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      alert(response.data.message); // Show success message
      setError(""); // Clear any previous errors
    } catch (primaryError) {
      console.warn("Primary API failed, trying fallback:", primaryError);

      // Attempt to submit data to the fallback API URL
      try {
        const fallbackResponse = await axios.post(FALLBACK_API_URL, signupData, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        alert(fallbackResponse.data.message); // Show success message
        setError(""); // Clear any previous errors
      } catch (fallbackError) {
        console.error("Fallback API failed:", fallbackError);
        setError(
          fallbackError.response?.data?.message ||
            "Error signing up. Please try again later."
        );
      }
    }
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSubmit}>
        <h2>Sign Up</h2>
        {error && <p className="error-message">{error}</p>}

        <input
          type="text"
          name="name"
          placeholder="Name"
          value={formData.name}
          onChange={handleChange}
          required
        />
        <input
          type="email"
          name="email"
          placeholder="Email"
          value={formData.email}
          onChange={handleChange}
          required
        />
        <div className="password-container">
          <input
            type={showPassword.password ? "text" : "password"}
            name="password"
            placeholder="Password"
            value={formData.password}
            onChange={handleChange}
            required
          />
          <span
            className="toggle-password"
            onClick={() =>
              setShowPassword((prev) => ({
                ...prev,
                password: !prev.password,
              }))
            }
          >
            {showPassword.password ? "👁" : "👁️"}
          </span>
        </div>
        <div className="password-container">
          <input
            type={showPassword.confirmPassword ? "text" : "password"}
            name="confirmPassword"
            placeholder="Confirm Password"
            value={formData.confirmPassword}
            onChange={handleChange}
            required
          />
          <span
            className="toggle-password"
            onClick={() =>
              setShowPassword((prev) => ({
                ...prev,
                confirmPassword: !prev.confirmPassword,
              }))
            }
          >
            {showPassword.confirmPassword ? "👁" : "👁️"}
          </span>
        </div>

        <input
          type="file"
          name="photo"
          accept="image/*"
          onChange={handleChange}
          required
        />
        <button type="submit">Sign Up</button>
        <p>
          Already have an account?{" "}
          <Link to="/login" style={{ color: "#734F96", textDecoration: "none" }}>
            Login here
          </Link>
        </p>
      </form>
    </div>
  );
};

export default SignupForm;
