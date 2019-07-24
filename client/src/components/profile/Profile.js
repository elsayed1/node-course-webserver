import React, { Component } from 'react';
import { connect } from 'react-redux';
import { Link } from 'react-router-dom';
import  isEmpty  from '../../validation/isEmpty';
import { getProfiles } from '../../actions/profileActions';
import Loading from '../common/Loading';
import ProfileHeader from './ProfileHeader';
import ProfileCred from './ProfileCred';
import ProfileGithub from './ProfileGithub';
import ProfileAbout from './ProfileAbout';
class Profile extends Component {
    constructor(props){
        super(props);
        this.state = {
            profile: null
        }
    }
    componentDidMount(){
         if(!this.props.profiles)
            this.props.getProfiles();
        else
            this.setState({
                profile: this.props.profiles.find((profile) => profile.handle === this.props.match.params.handle)
            })
    }
 componentWillReceiveProps(nextProps){
     if(nextProps.profiles){
         this.setState({
             profile: nextProps.profiles.find((profile) => profile.handle === this.props.match.params.handle)
         })
     }
 }
  render() {
    const { profile } = this.state;
    if(profile === null){
        return(
            <Loading />
        )
    }
    else if(profile === undefined){
        return(
            <h2 className="alert alert-danger text-center">
                Handle doesn't exist
            </h2>
        )
    }
    else
        return (
        <div className="profile"
        style={{
            minHeight: '86vh'
        }}>
            <div className="container">
                <div className="row">
                    <div className="col-md-12">
                        <Link to='/profiles' className='btn btn-warning my-3'>
                            All Profiles
                        </Link>
                    </div>
                </div>
                <div className="row">
                    <div className="col-md-12">
                    <ProfileHeader profile={profile}/>
                    <ProfileAbout profile={profile}/>
                    <ProfileCred education={profile.education} experience={profile.experience}/>
                    {isEmpty(profile.githubusername)?null:(
                        <ProfileGithub username={profile.githubusername}/>
                    )}
                    </div>
                </div>
            </div>
        </div>
        )
  }
}
const mapStateToProps = (state) => (
    {
        profiles: state.profile.profiles
    }
)
export default connect(mapStateToProps, { getProfiles })(Profile);
