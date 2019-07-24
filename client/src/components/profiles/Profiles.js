import React, { Component } from 'react';
import { connect } from 'react-redux';
import Loading from '../common/Loading';
import ProfileItem from './ProfileItem'
import { getProfiles } from '../../actions/profileActions';
class Profiles extends Component {
 constructor(props){
     super(props);
     this.state = {
         profiles: null,
         errors: null
     }
 }
 componentDidMount(){
     this.props.getProfiles();
 }
 componentWillReceiveProps(nextProps){
    if(nextProps.errors)
        this.setState({
            errors: nextProps.errors
        })
    if(nextProps.profiles)
        this.setState({
            profiles: nextProps.profiles
        })
 }
  render() {
    const { profiles } = this.state;
    console.log(profiles);
    if(profiles === null){
        return(
            <Loading />
        )
    }else{
        let profilesHtml = (
                <div className="alert alert-danger text-center">
                    There is no profiles yet
                </div>
            )
        if(profiles.length > 0){
            profilesHtml = (
                <div>
                    <h2 className='display-4 text-center text-info my-2'>Developers Profiles</h2>
                    {profiles.map((item, index) => <ProfileItem profile={item} key={index} /> )}
                </div>
            )
        }
        return(
            <div className="profiles">
                <div className="container">
                    <div className="row">
                        <div className="col-md-12 m-auto">
                            {profilesHtml}
                        </div>
                    </div>
                </div>
            </div>
        )
    }
  }
}
const mapStateToProps = (state) => (
    {
        profiles: state.profile.profiles
    }
)
export default connect(mapStateToProps, { getProfiles })(Profiles);
