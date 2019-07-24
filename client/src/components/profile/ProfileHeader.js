import React, { Component } from 'react';
import SuitPerson from '../suitperson.jpg';
import isEmpty from '../../validation/isEmpty';
class ProfileHeader extends Component {
  render() {
      const { profile } = this.props;
      console.log(profile);
    return (
        <div className="card text-center bg-dark">
        <img 
            src={SuitPerson} 
            alt="Dummy Person" 
            className="rounded-circle mx-auto my-2"
            width='200px'
            height='200px'/>
        <div className="card-body text-white">
          <h5 className="card-title">{profile.user.name}</h5>
          <p className='lead'>
                {profile.status} {isEmpty(profile.company)?null:(<span>at {profile.company}</span>)}
          </p>
          <p>
              {isEmpty(profile.website)?null:(
                  <a 
                  href={profile.website} 
                  className="text-white p-2"
                  target='__blank'>
                    <i className="fas fa-globe fa-2x" />
                  </a>
              )}
              {isEmpty(profile.social && profile.social.gmail)?null:(
                  <a 
                  href={profile.social.gmail} 
                  className="text-white p-2"
                  target='__blank'>
                    <i className="fab fa-google fa-2x" />
                  </a>
              )}
              {isEmpty(profile.social && profile.social.facebook)?null:(
                  <a 
                  href={profile.social.facebook} 
                  className="text-white p-2"
                  target='__blank'>
                    <i className="fab fa-facebook fa-2x" />
                  </a>
              )}
              {isEmpty(profile.social && profile.social.twitter)?null:(
                  <a 
                  href={profile.social.twitter} 
                  className="text-white p-2"
                  target='__blank'>
                    <i className="fab fa-twitter fa-2x" />
                  </a>
              )}
              {isEmpty(profile.social && profile.social.youtube)?null:(
                  <a 
                  href={profile.social.youtube} 
                  className="text-white p-2"
                  target='__blank'>
                    <i className="fab fa-youtube fa-2x" />
                  </a>
              )}
          </p>

        </div>
      </div>
    )
  }
}
export default ProfileHeader;
