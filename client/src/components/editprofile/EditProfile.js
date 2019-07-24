import React, { Component } from 'react';
import { withRouter } from 'react-router-dom';
import { connect } from 'react-redux';
import TextFieldGroup from '../common/TextFieldGroup';
import TextAreaFieldGroup from '../common/TextAreaFieldGroup';
import SelectListFieldGroup from '../common/SelectListFieldGroup';
import InputGroup from '../common/InputGroup';
import { createProfile, getCurrentProfile } from '../../actions/profileActions';
class EditProfile extends Component {
  constructor(props){
    super(props);
    this.state = {
      displaySocialInput: false,
      profile: {
        handle: '',
        company: '',
        website: '',
        location: '',
        status  : '',
        skills  : '',
        bio     : '',
        githubusername: '',
        social: {
            gmail: '',
            facebook: '',
            twitter: '',
            youtube: ''
        }
      },
      errors: {}
    }
  }
  componentDidMount(){
      this.props.getCurrentProfile();
  }
  componentWillReceiveProps = nextProps => {
    if(nextProps.errors)
      this.setState({
        errors: nextProps.errors
      })
    if(nextProps.profile.profile){
        let profile = nextProps.profile.profile;
        if(!profile.social)
            profile.social = {};
        if(!profile.social.gmail) profile.social.gmail = '';
        if(!profile.social.facebook) profile.social.facebook = '';
        if(!profile.social.twitter) profile.social.twitter = '';
        if(!profile.social.youtube) profile.social.youtube = '';
        this.setState({
            profile
        })
    }
    else{
        this.props.history('/dashboard');
    }
  }
  submit = e => {
    e.preventDefault();
    let profile = {};
    profile.handle = document.getElementById('handle_id').value;
    profile.status = document.getElementById('status_id').value==='0'?null:document.getElementById('status_id').value;
    profile.company = document.getElementById('company_id').value;
    profile.location = document.getElementById('location_id').value;
    profile.skills = document.getElementById('skills_id').value;
    profile.website = document.getElementById('website_id').value;
    profile.githubusername = document.getElementById('githubusername_id').value;
    profile.bio = document.getElementById('bio_id').value;
    profile.gmail = this.state.profile.social.gmail;
    profile.facebook = this.state.profile.social.facebook;
    profile.twitter = this.state.profile.social.twitter;
    profile.youtube = this.state.profile.social.youtube;
    this.props.createProfile(profile, this.props.history);
  }
  changeStatus = (e) => {
      let { profile } = this.state;
      profile.status = e.target.value;
      this.setState({
          profile
      })
  }
  changeSocialInput = (e) => {
      let { profile } = this.state;
      profile.social[e.target.name] = e.target.value;
      this.setState({
          profile
      })
  }
  render() {
    const { profile } = this.state;
    console.log(profile);
    if(profile){
        if(Object.entries(profile).length === 0)
            this.props.history.push('/dashboard');
    }
    const professionalOptions = [
      {label: 'Select Professinoal Option', value:'' },
      {label: 'Developer', value:'developer'},
      {label: 'Juior Developer', value:'junior developer'},
      {label: 'Senior Developer', value:'senior developer'},
      {label: 'Manager', value:'manager'},
      {label: 'Student', value:'student'},
      {label: 'Instructor', value:'instructor'},
      {label: 'Intern', value:'intern'},
      {label: 'Other', value:'other'}
    ]
    const socialInputs = this.state.displaySocialInput ?(
      <div className='col-md-8 m-auto'>
      <InputGroup
      errors={this.state.errors}
      id='gmail_id'
      placeholder='Gmail Acccount'
      type='text'
      value={profile.social.gmail}
      changeSocialInput={this.changeSocialInput}
      name='gmail'
      icon='fab fa-google'
      />
      <InputGroup
      errors={this.state.errors}
      id='facebook_id'
      placeholder='Facebook Acccount'
      type='text'
      value={profile.social.facebook}
      changeSocialInput={this.changeSocialInput}
      name='facebook'
      icon='fab fa-facebook'
      />
      <InputGroup
      errors={this.state.errors}
      id='twitter_id'
      placeholder='Twitter Acccount'
      type='text'
      value={profile.social.twitter}
      changeSocialInput={this.changeSocialInput}
      name='twitter'
      icon='fab fa-twitter'
      />
      <InputGroup
      errors={this.state.errors}
      id='youtube_id'
      placeholder='Youtube Acccount'
      type='text'
      value={profile.social.youtube}
      changeSocialInput={this.changeSocialInput}
      name='youtube'
      icon='fab fa-youtube'
      />
      </div>
    ): null;
    return (
      <form 
      onSubmit={this.submit}
      className='container'>
        <div className='row'>
          <div className='col-md-8 m-auto'>
            <h2 className='text-center text-muted mt-2'>Create Your Profile</h2>
          </div>
        </div>
          <TextFieldGroup
            label='handle'
            type='text'
            errors={this.state.errors}
            id='handle_id'
            placeholder='Enter Handle'
            name='handle'
            value={profile.handle}
            />
          <SelectListFieldGroup
          label='Choose Professional Status: '
          errors={this.state.errors}
          id='status_id'
          name='status'
          changeStatus={this.changeStatus}
          value={profile.status}
          values={professionalOptions}
          />
          <TextFieldGroup
            label='company'
            type='text'
            errors={this.state.errors}
            id='company_id'
            placeholder='Enter Company'
            name='company'
            value={profile.company}
            />
          <TextFieldGroup
            label='location'
            type='text'
            errors={this.state.errors}
            id='location_id'
            placeholder='Enter Location'
            name='location'
            value={profile.location}
            />
          <TextFieldGroup
            label='skills'
            type='text'
            errors={this.state.errors}
            id='skills_id'
            placeholder='Enter Skills'
            name='skills'
            value={profile.skills.toString()}
            />
          <TextFieldGroup
            label='website'
            type='text'
            errors={this.state.errors}
            id='website_id'
            placeholder='Enter Website'
            name='website'
            value={profile.website}
            />
          <TextFieldGroup
            label='Github username'
            type='text'
            errors={this.state.errors}
            value={profile.githubusername}
            id='githubusername_id'
            placeholder='Enter Github username'
            name='githubusername'
            />
          <TextAreaFieldGroup
          errors={this.state.errors}
          id='bio_id'
          placeholder='Short Bio'
          name='bio'
          value={profile.bio}
          />
          <div className="row mb-3 col-md-8 m-auto">
            <button 
            type='button'
            className="btn btn-light"
            onClick={(e)=>this.setState(prevState => ({
              displaySocialInput: !prevState.displaySocialInput
            }))}>
            Add Social Network Links
            </button>
          </div>
            {socialInputs}
            <input type="submit" value="Edit Profile" className="btn btn-success btn-block mt-4"/>
      </form>
    )
  }
}
const mapStateToProps = state => (
  {
    errors: state.errors,
    profile: state.profile
  }
)
export default connect(mapStateToProps, { createProfile, getCurrentProfile })(withRouter(EditProfile));
