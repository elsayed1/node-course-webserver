import axios from "axios";
import jwt_decode from "jwt-decode";
import setAuthToken from "../utils/setAuthToken";
import { clearProfile } from "./profileActions";
export const registerUser = (userData, history) => dispatch => {
  axios
    .post("/api/users/register", userData)
    .then(result => {
      history.push("/login");
    })
    .catch(err => {
      dispatch({
        type: "GET-ERRORS",
        payload: err.response.data
      });
    });
};

export const loginUser = userData => dispatch => {
  axios
    .post("/api/users/login", userData)
    .then(result => {
      const { token } = result.data;
      localStorage.setItem("jwttoken", token);
      setAuthToken(token);
      const decoded = jwt_decode(token);
      dispatch({
        type: "SET_CURRENT_USER",
        payload: decoded
      });
    })
    .catch(err => {
      console.log(err.response);
      dispatch({
        type: "GET-ERRORS",
        payload: err.response.data
      });
    });
};
export const setCurrentUser = decoded => {
  return {
    type: "SET_CURRENT_USER",
    payload: decoded
  };
};
export const logoutUser = () => dispatch => {
  // Remove Item from local storage
  localStorage.removeItem("jwttoken");
  // Remove Default Header
  setAuthToken(false);
  // Remove user from state
  dispatch(setCurrentUser({}));
  // Remove current profile
  dispatch(clearProfile());
};
