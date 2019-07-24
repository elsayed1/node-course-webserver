import React from 'react';
import classnames from 'classnames';
function TextAreaFieldGroup({
    errors,
    id,
    placeholder,
    value,
    name
}) {
  return (
    <div className='row my-3'>
    <div className="form-group col-md-8">
        <textarea 
        className= {classnames("form-control", {
        'is-invalid': errors[name],
        })}
        id={id}
        aria-describedby="emailHelp" 
        placeholder={placeholder}
        defaultValue={value} 
        />
        {errors[name]?(
        <small className='form-text text-danger'>
            {errors[name]}
        </small>
        ):null}
  </div>
  </div>
  )
}
export default TextAreaFieldGroup;
