import React, { Component } from 'react';
import { connect } from 'react-redux';
import './css/landing.css';
class Landing extends Component{
  render(){
    return (
      <div className='landing'
      style={{
        height: 'calc( 100vh - (56px + 54px ) )',
        background: `url(${require('./images/connect.jpeg')}) no-repeat center center`
      }}>
        <div 
        className='landing-layout text-center text-white'>
          <div 
          className='container w-75 p-4'
          style={{
            margin: '110px auto',
            background: 'rgba(255, 255, 255, .1)',
            borderRadius: '10px'
          }}>
            <h1 
            style={{
              fontFamily: "'Oswald', sans-serif",
              letterSpacing: '3px',
              fontSize: '70px'
            }}
            className='text-uppercase'>Developer Connect Website</h1>
            <p 
            style={{
              fontWeight: 'bold'
            }}
            className='lead p-2'>You can create you own profile and other developers see it also you can create you own posts and comments</p>
          </div>
        </div>
      </div>
    )
  }
}
const mapStateToProps = (state) =>(
  {
    auth: state.auth
  }
)
export default  connect(mapStateToProps)(Landing);
