import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import  Loading  from '../common/Loading';
import { connect } from 'react-redux';
import { getCurrentProfile, deleteAccount } from '../../actions/profileActions';
import ProfileActions  from './ProfileActions';
import Experience from './Experience';
import Education from './Education';
class Dashboard extends Component {
    constructor(){
        super();
        this.state = {
            profile: null
        }
    }
    componentDidMount(){
        this.props.getCurrentProfile();
    }
    componentWillReceiveProps(nextProps){
        this.setState({
            profile: nextProps.profile.profile
        })
    }
    deleteProfile = (e) => {
        this.props.deleteAccount();
    }
  render() {
      const { profile } = this.state;
      let experience = null;
      if(profile !== null && profile.experience)
        experience = profile.experience;
        let education = null;
        if(profile !== null && profile.education)
          education = profile.education;
      const dynamicContent = profile === null ? (
          <Loading />
      ): Object.entries(profile).length === 0 ? (
          <p className='alert alert-danger text-center text-capitalize mt-3'>You Must Create Profile <Link exact='true' to='/createprofile' className='alert-link'> Click Here</Link> to create profile</p>
      ):(
          <div>
              <h2 className='my-3'>
                Welcome &nbsp;
                <Link 
                to={`/profile/${profile.handle}`}
                className='text-info'>
                    {profile.handle}
                </Link>
              </h2>
              <ProfileActions />
              <div style={{
                  marginBottom: "30px"
              }}>
                <button 
                onClick={this.deleteProfile}
                className='btn btn-danger'>
                Delete My Account
                </button>
              </div>
              <Experience experience={experience}/>
              <Education education={education}/>
          </div>
      )
      return(
          <div className='dashboard'
          style={{
              minHeight: '83.5vh'
          }}>
              <div className='container'>
                {dynamicContent}
              </div>
          </div>
      );
  }
}
const mapStateToProps = (state) => (
    {
        auth   : state.auth,
        profile: state.profile
    }
)
export default connect(mapStateToProps, { getCurrentProfile, deleteAccount })(Dashboard);
