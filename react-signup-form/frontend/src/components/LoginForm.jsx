import { useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import './SignupForm.css'; // Reuse existing styles

const LoginForm = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Backend URLs
  const PRIMARY_API_URL = 'https://numetry-signupform-backend.vercel.app/api/login';
  const FALLBACK_API_URL = 'http://localhost:5000/api/login';

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    setError(''); // Clear error when the user types
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      // Attempt to submit data to the primary API URL
      const response = await axios.post(PRIMARY_API_URL, formData);
      alert(response.data.message); // Show success message
      setError(''); // Clear any previous errors
    } catch (primaryError) {
      console.warn('Primary API failed, trying fallback:', primaryError);

      // Attempt to submit data to the fallback API URL
      try {
        const fallbackResponse = await axios.post(FALLBACK_API_URL, formData);
        alert(fallbackResponse.data.message); // Show success message
        setError(''); // Clear any previous errors
      } catch (fallbackError) {
        console.error('Fallback API failed:', fallbackError);
        setError(
          fallbackError.response?.data?.message ||
            'Error logging in. Please try again later.'
        );
      }
    }
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSubmit}>
        <h2>Login</h2>
        {error && <p className="error-message">{error}</p>}

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
            type={showPassword ? 'text' : 'password'}
            name="password"
            placeholder="Password"
            value={formData.password}
            onChange={handleChange}
            required
          />
          <span
            className="toggle-password"
            onClick={() => setShowPassword(!showPassword)}
          >
            {showPassword ? '👁' : '👁️'}
          </span>
        </div>
        <button type="submit">Login</button>
        <p>
          Don’t have an account?{' '}
          <Link to="/" style={{ color: '#734F96', textDecoration: 'none' }}>
            Sign up here
          </Link>
        </p>
      </form>
    </div>
  );
};

export default LoginForm;
