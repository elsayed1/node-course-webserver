import React, { Component } from 'react';
import {Link, NavLink } from 'react-router-dom';
import { connect } from 'react-redux';
import { logoutUser } from '../actions/authAction';
import  dummyImage  from './dummyperson.jpg';
class Navbar extends Component {
  logout = (e) => {
    //   e.preventDefault();
      this.props.logoutUser();
  }
  render() {
    const { auth } = this.props;
    let dynamicLinks = !auth.isAuthenticated?(
        <React.Fragment>
            <li className="nav-item">
                <NavLink  className="nav-link" exact to="/login">Login</NavLink>
            </li>
            <li className="nav-item">
                <NavLink  className="nav-link" exact to="/signup">Signup</NavLink>
            </li>
        </React.Fragment>
    ):(
        <React.Fragment>
            <li className="nav-item">
                <NavLink  className="nav-link" exact to="/posts">Posts</NavLink>
            </li>
            <li className="nav-item">
                <NavLink  className="nav-link" exact to="/addpost">Add Post</NavLink>
            </li>
            <li className="nav-item">
                <NavLink  className="nav-link" exact to="/dashboard">Dashboard</NavLink>
            </li>
            <li className="nav-item">
                <NavLink  className="nav-link" exact to="/" onClick={this.logout}>
                <img 
                src={dummyImage}
                alt='dummy person'
                style={{
                    width: "30px",
                    height: "30px",
                    borderRadius: "50%",
                    marginRight: '5px'
                }} />
                logout
                </NavLink>
            </li>
        </React.Fragment>
    )
    return (
    <nav style={{
        position: 'fixed',
        width: '100%',
        top: '0',
        left: '0',
        zIndex: '99999'
    }} className="navbar navbar-expand-lg navbar-dark bg-dark">
        <div className='container'>
        <Link className="navbar-brand" exact="true" to="/">Connect</Link>
    <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
        <span className="navbar-toggler-icon"></span>
    </button>

    <div className="collapse navbar-collapse" id="navbarSupportedContent">
        <ul className="navbar-nav mx-auto">
        <li className="nav-item">
            <NavLink  className="nav-link" exact  to="/profiles">Profiles</NavLink>
        </li>
        {dynamicLinks}
        </ul>
        </div>
        </div>
    </nav>
    )
  }
}
const mapStateToProps = state => ({
    auth: state.auth
})
export default connect(mapStateToProps, { logoutUser })(Navbar);