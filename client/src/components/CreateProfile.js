import React, { Component } from 'react';
import { withRouter } from 'react-router-dom';
import { connect } from 'react-redux';
import TextFieldGroup from './common/TextFieldGroup';
import TextAreaFieldGroup from './common/TextAreaFieldGroup';
import SelectListFieldGroup from './common/SelectListFieldGroup';
import InputGroup from './common/InputGroup';
import { createProfile } from '../actions/profileActions';
class CreateProfile extends Component {
  constructor(props){
    super(props);
    this.state = {
      displaySocialInput: false,
      handle: '',
      company: '',
      website: '',
      location: '',
      status  : '',
      skills  : '',
      bio     : '',
      githubusername: '',
      gmail: '',
      facebook: '',
      twitter: '',
      youtube: '',
      errors: {}
    }
  }
  componentWillReceiveProps = nextProps => {
    if(nextProps.errors)
      this.setState({
        errors: nextProps.errors
      })
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
    if(this.state.displaySocialInput){
      profile.gmail = document.getElementById('gmail_id').value;
      profile.facebook = document.getElementById('facebook_id').value;
      profile.twitter = document.getElementById('twitter_id').value;
      profile.youtube = document.getElementById('youtube_id').value;
    }
    this.props.createProfile(profile, this.props.history);
  }
  render() {
    const professionalOptions = [
      {label: 'Select Professinoal Option', value:0 },
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
      value={this.state.gmail}
      name='gmail'
      icon='fab fa-google'
      />
      <InputGroup
      errors={this.state.errors}
      id='facebook_id'
      placeholder='Facebook Acccount'
      type='text'
      value={this.state.gmail}
      name='facebook'
      icon='fab fa-facebook'
      />
      <InputGroup
      errors={this.state.errors}
      id='twitter_id'
      placeholder='Twitter Acccount'
      type='text'
      value={this.state.gmail}
      name='twitter'
      icon='fab fa-twitter'
      />
      <InputGroup
      errors={this.state.errors}
      id='youtube_id'
      placeholder='Youtube Acccount'
      type='text'
      value={this.state.gmail}
      name='youtube'
      icon='fab fa-youtube'
      />
      </div>
    ): null;
    return (
      <div className='container'>
      <form 
      onSubmit={this.submit}
      className='custom-form'>
        <h2 className="text-center">Create Your Own Profile</h2>
          <TextFieldGroup
            label='handle'
            type='text'
            errors={this.state.errors}
            id='handle_id'
            placeholder='Enter Handle'
            name='handle'
            />
          <SelectListFieldGroup
          label='Choose Professional Status: '
          errors={this.state.errors}
          id='status_id'
          name='status'
          value={0}
          values={professionalOptions}
          />
          <TextFieldGroup
            label='company'
            type='text'
            errors={this.state.errors}
            id='company_id'
            placeholder='Enter Company'
            name='company'
            />
          <TextFieldGroup
            label='location'
            type='text'
            errors={this.state.errors}
            id='location_id'
            placeholder='Enter Location'
            name='location'
            />
          <TextFieldGroup
            label='skills'
            type='text'
            errors={this.state.errors}
            id='skills_id'
            placeholder='Like: HTML,CSS'
            name='skills'
            />
          <TextFieldGroup
            label='website'
            type='text'
            errors={this.state.errors}
            id='website_id'
            placeholder='Enter Website'
            name='website'
            />
          <TextFieldGroup
            label='Github username'
            type='text'
            errors={this.state.errors}
            value={this.state.githubusername}
            id='githubusername_id'
            placeholder='Enter Github username'
            name='githubusername'
            />
          <TextAreaFieldGroup
          errors={this.state.errors}
          id='bio_id'
          placeholder='Short Bio'
          name='bio'
          value={this.state.bio}
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
            <button type="submit" className="btn btn-info btn-block mt-4">Create Profile</button>
      </form>
      </div>
    )
  }
}
const mapStateToProps = state => (
  {
    errors: state.errors,
    profile: state.profile
  }
)
export default connect(mapStateToProps, { createProfile })(withRouter(CreateProfile));
