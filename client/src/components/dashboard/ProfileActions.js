import React from 'react'
import { Link } from 'react-router-dom';
function ProfileActions() {
  return (
    <div className='btn-group mb-4' role='group'>
      <Link to='/editprofile' className='btn btn-light ml-2'>
        <i className='fas fa-user-circle text-info mr-2' />
        Edit Profile
      </Link>
      <Link to='/addeducation' className='btn btn-light ml-2'>
        <i className='fas fa-graduation-cap text-info mr-2' />
        Add Education
      </Link>
      <Link to='/addexperience' className='btn btn-light ml-2'>
        <i className="fas fa-briefcase text-info mr-2" />
        Add Experience
      </Link>
    </div>
  )
}
export default ProfileActions;
