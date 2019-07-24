import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import Suitperson from '../suitperson.jpg';
import isEmpty from '../../validation/isEmpty';
class ProfileItem extends Component {
  render() {
    const { profile } = this.props;
    return (
      <div className="card card-body bg-light mb-4">
        <div className="row">
            <div className="col-2">
            <img 
            src={Suitperson} 
            alt="Dummy Person" 
            className="rounded-circle"
            width='100%'/>
            </div>
            <div className="col-lg-6 col-md-4 col-8">
                <h3>{profile.user.name}</h3>
                <p className='lead'>
                {profile.status} {isEmpty(profile.company)?null:(<span>at {profile.company}</span>)}
                </p>
                {isEmpty(profile.location)?null:(
                    <p>{profile.location}</p>
                )}
                <Link to={`/profile/${profile.handle}`}
                className='btn btn-info'>
                    view Profile
                </Link>
            </div>
            <div className="col-md-4 d-none d-md-block">
                <h3>Skills Set</h3>
                <ul className="list-group">
                    {profile.skills.slice(0,3).map((item, index) => {
                        return(
                            <li className="list-group-item text-left" key={index}>
                                <i className="fa fa-check pr-1 text-info" />
                                {item}
                            </li>
                        )
                    })}
                </ul>
            </div>
        </div>
      </div>
    )
  }
}
export default ProfileItem;
