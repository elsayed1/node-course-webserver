import React, { Component } from 'react';
import isEmpty from '../../validation/isEmpty';

class ProfileCred extends Component {
  render() {
    const { education, experience } = this.props;
    let expItems = (
      <li className="alert alert-danger text-center">
        There is no experience for this user
      </li>
    )
    let eduItems = (
      <li className="alert alert-danger text-center">
        There is no education for this user
      </li>
    )
    if(experience.length > 0)
    expItems = experience.map((exp, index) => {
      return(
        <li 
        className="list-group-item"
        key={index}>
          <h4>{exp.company}</h4>
          <p>
          {exp.from.slice(0, exp.from.indexOf('T'))} - 
          {exp.to?exp.to.slice(0, exp.to.indexOf('T')):
            new Date().getFullYear() + '-' + new Date().getMonth() + '-'+ new Date().getDate()
          }
          </p>
          <p><strong>Position: </strong>{exp.title}</p>
          {isEmpty(exp.location)?null:<p>
            <strong>Location {exp.location}</strong>
          </p>}
          {isEmpty(exp.description)?null:<p>
            <strong>Description {exp.description}</strong>
          </p>}
        </li>
      )
    });
    if(education.length > 0)
    eduItems = education.map((edu, index) => {
      console.log(edu.description);
      return(
        <li 
        className="list-group-item"
        key={index}>
          <h4>{edu.school}</h4>
          <p>
          {edu.from.slice(0, edu.from.indexOf('T'))} - 
          {edu.to?edu.to.slice(0, edu.to.indexOf('T')):
            new Date().getFullYear() + '-' + new Date().getMonth() + '-'+ new Date().getDate()
          }
          </p>
          <p><strong>Degree: </strong>{edu.degree}</p>
          <p>
            <strong>Field Of Study: </strong>{edu.fieldOfStudy}
          </p>
          {isEmpty(edu.description)?null:<p>
            <strong>Description {edu.description}</strong>
          </p>}
        </li>
      )
    });
    return (
      <div className="row">
        <div className="col-md-6">
          <h3 className="text-center text-info">Experience</h3>
          <ul className="list-group">
            {expItems}
          </ul>
        </div>
        <div className="col-md-6">
          <h3 className="text-center text-info">Education</h3>
          <ul className="list-group">
            {eduItems}
          </ul>
        </div>
      </div>
    )
  }
}
export default ProfileCred;
