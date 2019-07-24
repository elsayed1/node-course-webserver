import React, { Component } from 'react'
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import { removeExperience } from '../../actions/profileActions';

class Experience extends Component {
  render() {
    const { experience } = this.props;
    console.log(experience);
    let result = null;
    if(experience.length === 0)
        result = (
            <div className="alert alert-danger d-block w-50 m-auto text-center">
                There is no added experience yet
            </div>
        )
    else{
        const experienceRows = experience.map((item, index) => {
            let endDate = item.to;
            if(!item.to){
                let d = new Date();
                endDate = `${d.getFullYear()}-${d.getMonth()+1}-${d.getDate()}`;
            }
            return(
                <tr key={index}>
                    <th>{index+1}</th>
                    <td>{item.title}</td>
                    <td>{item.company}</td>
                    <td>{item.location}</td>
                    <td>{item.from.slice(0, item.from.indexOf('T')) + ' :: ' + endDate}</td>
                    <td>
                        <button 
                        className="btn btn-danger"
                        onClick={(e) => {
                            e.preventDefault();
                            if(window.confirm('Are you sure you want to delete experience ?')){
                                this.props.removeExperience(item._id);
                            }
                        }}>
                            Delete
                        </button>
                    </td>
                </tr>
            )
        });
        result = (
            <table className="table table-striped">
                <thead>
                    <tr>
                    <th>#</th>
                    <th>Title</th>
                    <th>Company</th>
                    <th>Location</th>
                    <th>Years</th>
                    <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {experienceRows}
                </tbody>
            </table>
        )
    }
    return(
        <div className='experience'>
            <div className='container'>
                <div className='row'>
                    <div className='col-md-12'>
                        <h2 className="text-info mb-5">
                            <span style={{
                                borderBottom: '4px solid #17a2b8',
                                paddingBottom: '5px'
                            }}>Exper</span>ience Section
                        </h2>
                        {result}
                    </div>
                </div>
            </div>
        </div>
    )
  }
}
export default connect(null, { removeExperience })(withRouter(Experience));
