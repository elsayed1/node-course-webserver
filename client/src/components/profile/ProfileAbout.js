import React, { Component } from 'react'

class ProfileAbout extends Component {
  render() {
    const { profile } = this.props;
    const firstName = profile.user.name.trim().split(' ')[0];
    const skillsSet = profile.skills.map((skill, index) => {
      return(
        <div 
        className="p-3"
        key={index}>
        <i className="fa fa-check text-success p-3" />
          {skill}
        </div>
      )
    })
    return (
      <div className="row">
        <div className="col-md-12">
          <div className="card-body bg-ligh mb-3">
            <h3 className="text-center text-info">
              {firstName}'s Bio
            </h3>
            <p className="lead">
              Lorem ipsum dolor sit amet consectetur adipisicing elit. 
              Consequuntur quos accusantium exercitationem nam cum sed 
              reprehenderit omnis dignissimos quibusdam ad qui blanditiis 
              voluptatibus eligendi, eveniet architecto, at reiciendis? 
              Sapiente, suscipit.
            </p>
            <hr />
            <h3 className="text-center text-info">
              Skills Set
            </h3>
            <div className="d-flex flex-wrap justify-content-center align-items-center">
              {skillsSet}
            </div>
          </div>
        </div>
      </div>
    )
  }
}
export default ProfileAbout;
